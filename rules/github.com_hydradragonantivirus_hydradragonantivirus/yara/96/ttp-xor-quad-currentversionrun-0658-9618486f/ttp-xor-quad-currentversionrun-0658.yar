rule TTP_XOR_QUAD_CurrentVersionRun_0658 {
  strings:
    $key_0658 = { 55 37 [2] 71 39 [2] 5a 15 [2] 74 37 [2] 60 2c [2] 6f 36 [2] 71 2b [2] 73 2a [2] 68 2c [2] 74 2b [2] 68 04 }

  condition:
    any of them
}