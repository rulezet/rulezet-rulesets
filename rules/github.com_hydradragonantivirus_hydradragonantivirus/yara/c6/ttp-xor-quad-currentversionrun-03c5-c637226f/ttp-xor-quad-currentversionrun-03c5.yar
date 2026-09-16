rule TTP_XOR_QUAD_CurrentVersionRun_03c5 {
  strings:
    $key_03c5 = { 50 aa [2] 74 a4 [2] 5f 88 [2] 71 aa [2] 65 b1 [2] 6a ab [2] 74 b6 [2] 76 b7 [2] 6d b1 [2] 71 b6 [2] 6d 99 }

  condition:
    any of them
}