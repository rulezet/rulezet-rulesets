rule TTP_XOR_QUAD_CurrentVersionRun_2d24 {
  strings:
    $key_2d24 = { 7e 4b [2] 5a 45 [2] 71 69 [2] 5f 4b [2] 4b 50 [2] 44 4a [2] 5a 57 [2] 58 56 [2] 43 50 [2] 5f 57 [2] 43 78 }

  condition:
    any of them
}