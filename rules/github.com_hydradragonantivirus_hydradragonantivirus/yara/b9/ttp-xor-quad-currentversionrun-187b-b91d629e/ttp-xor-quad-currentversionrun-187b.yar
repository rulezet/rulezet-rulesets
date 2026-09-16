rule TTP_XOR_QUAD_CurrentVersionRun_187b {
  strings:
    $key_187b = { 4b 14 [2] 6f 1a [2] 44 36 [2] 6a 14 [2] 7e 0f [2] 71 15 [2] 6f 08 [2] 6d 09 [2] 76 0f [2] 6a 08 [2] 76 27 }

  condition:
    any of them
}