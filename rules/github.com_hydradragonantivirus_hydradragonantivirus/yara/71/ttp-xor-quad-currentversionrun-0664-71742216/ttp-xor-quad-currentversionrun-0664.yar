rule TTP_XOR_QUAD_CurrentVersionRun_0664 {
  strings:
    $key_0664 = { 55 0b [2] 71 05 [2] 5a 29 [2] 74 0b [2] 60 10 [2] 6f 0a [2] 71 17 [2] 73 16 [2] 68 10 [2] 74 17 [2] 68 38 }

  condition:
    any of them
}