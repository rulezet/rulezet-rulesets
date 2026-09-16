rule TTP_XOR_QUAD_CurrentVersionRun_1a7b {
  strings:
    $key_1a7b = { 49 14 [2] 6d 1a [2] 46 36 [2] 68 14 [2] 7c 0f [2] 73 15 [2] 6d 08 [2] 6f 09 [2] 74 0f [2] 68 08 [2] 74 27 }

  condition:
    any of them
}