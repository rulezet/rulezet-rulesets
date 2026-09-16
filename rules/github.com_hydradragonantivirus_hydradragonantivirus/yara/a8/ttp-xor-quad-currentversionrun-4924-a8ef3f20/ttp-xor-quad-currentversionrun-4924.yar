rule TTP_XOR_QUAD_CurrentVersionRun_4924 {
  strings:
    $key_4924 = { 1a 4b [2] 3e 45 [2] 15 69 [2] 3b 4b [2] 2f 50 [2] 20 4a [2] 3e 57 [2] 3c 56 [2] 27 50 [2] 3b 57 [2] 27 78 }

  condition:
    any of them
}