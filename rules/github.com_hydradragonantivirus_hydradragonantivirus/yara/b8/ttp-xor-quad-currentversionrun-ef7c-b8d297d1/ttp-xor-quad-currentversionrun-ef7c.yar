rule TTP_XOR_QUAD_CurrentVersionRun_ef7c {
  strings:
    $key_ef7c = { bc 13 [2] 98 1d [2] b3 31 [2] 9d 13 [2] 89 08 [2] 86 12 [2] 98 0f [2] 9a 0e [2] 81 08 [2] 9d 0f [2] 81 20 }

  condition:
    any of them
}