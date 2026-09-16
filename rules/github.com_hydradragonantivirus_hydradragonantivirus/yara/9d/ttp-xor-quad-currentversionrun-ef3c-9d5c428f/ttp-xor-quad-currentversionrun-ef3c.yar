rule TTP_XOR_QUAD_CurrentVersionRun_ef3c {
  strings:
    $key_ef3c = { bc 53 [2] 98 5d [2] b3 71 [2] 9d 53 [2] 89 48 [2] 86 52 [2] 98 4f [2] 9a 4e [2] 81 48 [2] 9d 4f [2] 81 60 }

  condition:
    any of them
}