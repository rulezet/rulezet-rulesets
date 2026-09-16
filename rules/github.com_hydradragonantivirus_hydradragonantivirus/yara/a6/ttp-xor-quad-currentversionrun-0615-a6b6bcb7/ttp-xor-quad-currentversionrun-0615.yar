rule TTP_XOR_QUAD_CurrentVersionRun_0615 {
  strings:
    $key_0615 = { 55 7a [2] 71 74 [2] 5a 58 [2] 74 7a [2] 60 61 [2] 6f 7b [2] 71 66 [2] 73 67 [2] 68 61 [2] 74 66 [2] 68 49 }

  condition:
    any of them
}