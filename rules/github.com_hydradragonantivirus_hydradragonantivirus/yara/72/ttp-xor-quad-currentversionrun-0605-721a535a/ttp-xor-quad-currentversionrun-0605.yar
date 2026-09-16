rule TTP_XOR_QUAD_CurrentVersionRun_0605 {
  strings:
    $key_0605 = { 55 6a [2] 71 64 [2] 5a 48 [2] 74 6a [2] 60 71 [2] 6f 6b [2] 71 76 [2] 73 77 [2] 68 71 [2] 74 76 [2] 68 59 }

  condition:
    any of them
}