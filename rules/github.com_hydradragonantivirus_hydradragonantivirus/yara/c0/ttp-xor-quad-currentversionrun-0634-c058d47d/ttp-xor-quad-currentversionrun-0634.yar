rule TTP_XOR_QUAD_CurrentVersionRun_0634 {
  strings:
    $key_0634 = { 55 5b [2] 71 55 [2] 5a 79 [2] 74 5b [2] 60 40 [2] 6f 5a [2] 71 47 [2] 73 46 [2] 68 40 [2] 74 47 [2] 68 68 }

  condition:
    any of them
}