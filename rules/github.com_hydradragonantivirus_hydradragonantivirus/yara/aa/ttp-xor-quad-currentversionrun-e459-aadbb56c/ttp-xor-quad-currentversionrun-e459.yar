rule TTP_XOR_QUAD_CurrentVersionRun_e459 {
  strings:
    $key_e459 = { b7 36 [2] 93 38 [2] b8 14 [2] 96 36 [2] 82 2d [2] 8d 37 [2] 93 2a [2] 91 2b [2] 8a 2d [2] 96 2a [2] 8a 05 }

  condition:
    any of them
}