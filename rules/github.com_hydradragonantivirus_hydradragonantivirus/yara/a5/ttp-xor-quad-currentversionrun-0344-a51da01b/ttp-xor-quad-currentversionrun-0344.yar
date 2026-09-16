rule TTP_XOR_QUAD_CurrentVersionRun_0344 {
  strings:
    $key_0344 = { 50 2b [2] 74 25 [2] 5f 09 [2] 71 2b [2] 65 30 [2] 6a 2a [2] 74 37 [2] 76 36 [2] 6d 30 [2] 71 37 [2] 6d 18 }

  condition:
    any of them
}