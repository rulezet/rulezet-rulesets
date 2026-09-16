rule TTP_XOR_QUAD_CurrentVersionRun_0414 {
  strings:
    $key_0414 = { 57 7b [2] 73 75 [2] 58 59 [2] 76 7b [2] 62 60 [2] 6d 7a [2] 73 67 [2] 71 66 [2] 6a 60 [2] 76 67 [2] 6a 48 }

  condition:
    any of them
}