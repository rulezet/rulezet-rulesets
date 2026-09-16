rule TTP_XOR_QUAD_CurrentVersionRun_ef0c {
  strings:
    $key_ef0c = { bc 63 [2] 98 6d [2] b3 41 [2] 9d 63 [2] 89 78 [2] 86 62 [2] 98 7f [2] 9a 7e [2] 81 78 [2] 9d 7f [2] 81 50 }

  condition:
    any of them
}