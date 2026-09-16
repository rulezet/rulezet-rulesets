rule TTP_XOR_QUAD_CurrentVersionRun_e407 {
  strings:
    $key_e407 = { b7 68 [2] 93 66 [2] b8 4a [2] 96 68 [2] 82 73 [2] 8d 69 [2] 93 74 [2] 91 75 [2] 8a 73 [2] 96 74 [2] 8a 5b }

  condition:
    any of them
}