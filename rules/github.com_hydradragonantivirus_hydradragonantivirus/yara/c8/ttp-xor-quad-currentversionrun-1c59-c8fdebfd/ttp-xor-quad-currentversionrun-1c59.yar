rule TTP_XOR_QUAD_CurrentVersionRun_1c59 {
  strings:
    $key_1c59 = { 4f 36 [2] 6b 38 [2] 40 14 [2] 6e 36 [2] 7a 2d [2] 75 37 [2] 6b 2a [2] 69 2b [2] 72 2d [2] 6e 2a [2] 72 05 }

  condition:
    any of them
}