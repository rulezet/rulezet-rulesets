rule TTP_XOR_QUAD_CurrentVersionRun_4624 {
  strings:
    $key_4624 = { 15 4b [2] 31 45 [2] 1a 69 [2] 34 4b [2] 20 50 [2] 2f 4a [2] 31 57 [2] 33 56 [2] 28 50 [2] 34 57 [2] 28 78 }

  condition:
    any of them
}