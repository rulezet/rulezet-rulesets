rule TTP_XOR_QUAD_CurrentVersionRun_3177 {
  strings:
    $key_3177 = { 62 18 [2] 46 16 [2] 6d 3a [2] 43 18 [2] 57 03 [2] 58 19 [2] 46 04 [2] 44 05 [2] 5f 03 [2] 43 04 [2] 5f 2b }

  condition:
    any of them
}