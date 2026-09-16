rule TTP_XOR_QUAD_CurrentVersionRun_4628 {
  strings:
    $key_4628 = { 15 47 [2] 31 49 [2] 1a 65 [2] 34 47 [2] 20 5c [2] 2f 46 [2] 31 5b [2] 33 5a [2] 28 5c [2] 34 5b [2] 28 74 }

  condition:
    any of them
}