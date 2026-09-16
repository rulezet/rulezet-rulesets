rule TTP_XOR_QUAD_CurrentVersionRun_1815 {
  strings:
    $key_1815 = { 4b 7a [2] 6f 74 [2] 44 58 [2] 6a 7a [2] 7e 61 [2] 71 7b [2] 6f 66 [2] 6d 67 [2] 76 61 [2] 6a 66 [2] 76 49 }

  condition:
    any of them
}