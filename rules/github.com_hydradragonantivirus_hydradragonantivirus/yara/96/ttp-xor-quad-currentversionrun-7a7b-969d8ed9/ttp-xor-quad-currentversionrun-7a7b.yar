rule TTP_XOR_QUAD_CurrentVersionRun_7a7b {
  strings:
    $key_7a7b = { 29 14 [2] 0d 1a [2] 26 36 [2] 08 14 [2] 1c 0f [2] 13 15 [2] 0d 08 [2] 0f 09 [2] 14 0f [2] 08 08 [2] 14 27 }

  condition:
    any of them
}