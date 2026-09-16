rule TTP_XOR_QUAD_CurrentVersionRun_e447 {
  strings:
    $key_e447 = { b7 28 [2] 93 26 [2] b8 0a [2] 96 28 [2] 82 33 [2] 8d 29 [2] 93 34 [2] 91 35 [2] 8a 33 [2] 96 34 [2] 8a 1b }

  condition:
    any of them
}