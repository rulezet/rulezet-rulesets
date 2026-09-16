rule TTP_XOR_QUAD_CurrentVersionRun_7a7c {
  strings:
    $key_7a7c = { 29 13 [2] 0d 1d [2] 26 31 [2] 08 13 [2] 1c 08 [2] 13 12 [2] 0d 0f [2] 0f 0e [2] 14 08 [2] 08 0f [2] 14 20 }

  condition:
    any of them
}