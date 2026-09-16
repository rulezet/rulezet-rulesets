rule TTP_XOR_QUAD_CurrentVersionRun_0c24 {
  strings:
    $key_0c24 = { 5f 4b [2] 7b 45 [2] 50 69 [2] 7e 4b [2] 6a 50 [2] 65 4a [2] 7b 57 [2] 79 56 [2] 62 50 [2] 7e 57 [2] 62 78 }

  condition:
    any of them
}