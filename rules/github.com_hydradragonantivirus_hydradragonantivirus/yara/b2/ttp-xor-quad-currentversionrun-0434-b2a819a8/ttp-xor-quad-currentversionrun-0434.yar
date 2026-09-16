rule TTP_XOR_QUAD_CurrentVersionRun_0434 {
  strings:
    $key_0434 = { 57 5b [2] 73 55 [2] 58 79 [2] 76 5b [2] 62 40 [2] 6d 5a [2] 73 47 [2] 71 46 [2] 6a 40 [2] 76 47 [2] 6a 68 }

  condition:
    any of them
}