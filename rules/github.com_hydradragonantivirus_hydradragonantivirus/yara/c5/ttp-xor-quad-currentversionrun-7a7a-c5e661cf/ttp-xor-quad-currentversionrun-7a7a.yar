rule TTP_XOR_QUAD_CurrentVersionRun_7a7a {
  strings:
    $key_7a7a = { 29 15 [2] 0d 1b [2] 26 37 [2] 08 15 [2] 1c 0e [2] 13 14 [2] 0d 09 [2] 0f 08 [2] 14 0e [2] 08 09 [2] 14 26 }

  condition:
    any of them
}