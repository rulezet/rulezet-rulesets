rule TTP_XOR_QUAD_CurrentVersionRun_0c59 {
  strings:
    $key_0c59 = { 5f 36 [2] 7b 38 [2] 50 14 [2] 7e 36 [2] 6a 2d [2] 65 37 [2] 7b 2a [2] 79 2b [2] 62 2d [2] 7e 2a [2] 62 05 }

  condition:
    any of them
}