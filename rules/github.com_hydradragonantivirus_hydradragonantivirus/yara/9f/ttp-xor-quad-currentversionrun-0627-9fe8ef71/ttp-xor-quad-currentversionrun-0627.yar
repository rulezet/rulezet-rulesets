rule TTP_XOR_QUAD_CurrentVersionRun_0627 {
  strings:
    $key_0627 = { 55 48 [2] 71 46 [2] 5a 6a [2] 74 48 [2] 60 53 [2] 6f 49 [2] 71 54 [2] 73 55 [2] 68 53 [2] 74 54 [2] 68 7b }

  condition:
    any of them
}