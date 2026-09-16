rule TTP_XOR_QUAD_CurrentVersionRun_5d24 {
  strings:
    $key_5d24 = { 0e 4b [2] 2a 45 [2] 01 69 [2] 2f 4b [2] 3b 50 [2] 34 4a [2] 2a 57 [2] 28 56 [2] 33 50 [2] 2f 57 [2] 33 78 }

  condition:
    any of them
}