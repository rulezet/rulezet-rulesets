rule TTP_XOR_QUAD_CurrentVersionRun_0329 {
  strings:
    $key_0329 = { 50 46 [2] 74 48 [2] 5f 64 [2] 71 46 [2] 65 5d [2] 6a 47 [2] 74 5a [2] 76 5b [2] 6d 5d [2] 71 5a [2] 6d 75 }

  condition:
    any of them
}