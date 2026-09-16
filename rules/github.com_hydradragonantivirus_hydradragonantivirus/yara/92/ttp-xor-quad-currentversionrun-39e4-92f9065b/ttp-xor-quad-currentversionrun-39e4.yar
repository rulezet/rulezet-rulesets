rule TTP_XOR_QUAD_CurrentVersionRun_39e4 {
  strings:
    $key_39e4 = { 6a 8b [2] 4e 85 [2] 65 a9 [2] 4b 8b [2] 5f 90 [2] 50 8a [2] 4e 97 [2] 4c 96 [2] 57 90 [2] 4b 97 [2] 57 b8 }

  condition:
    any of them
}