rule TTP_XOR_QUAD_CurrentVersionRun_0e44 {
  strings:
    $key_0e44 = { 5d 2b [2] 79 25 [2] 52 09 [2] 7c 2b [2] 68 30 [2] 67 2a [2] 79 37 [2] 7b 36 [2] 60 30 [2] 7c 37 [2] 60 18 }

  condition:
    any of them
}