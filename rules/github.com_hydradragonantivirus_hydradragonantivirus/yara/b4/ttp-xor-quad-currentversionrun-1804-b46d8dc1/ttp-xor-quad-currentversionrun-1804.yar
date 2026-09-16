rule TTP_XOR_QUAD_CurrentVersionRun_1804 {
  strings:
    $key_1804 = { 4b 6b [2] 6f 65 [2] 44 49 [2] 6a 6b [2] 7e 70 [2] 71 6a [2] 6f 77 [2] 6d 76 [2] 76 70 [2] 6a 77 [2] 76 58 }

  condition:
    any of them
}