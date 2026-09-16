rule TTP_XOR_QUAD_CurrentVersionRun_0314 {
  strings:
    $key_0314 = { 50 7b [2] 74 75 [2] 5f 59 [2] 71 7b [2] 65 60 [2] 6a 7a [2] 74 67 [2] 76 66 [2] 6d 60 [2] 71 67 [2] 6d 48 }

  condition:
    any of them
}