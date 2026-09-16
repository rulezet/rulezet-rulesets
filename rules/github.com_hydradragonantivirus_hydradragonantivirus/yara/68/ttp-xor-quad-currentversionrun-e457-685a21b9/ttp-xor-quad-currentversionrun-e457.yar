rule TTP_XOR_QUAD_CurrentVersionRun_e457 {
  strings:
    $key_e457 = { b7 38 [2] 93 36 [2] b8 1a [2] 96 38 [2] 82 23 [2] 8d 39 [2] 93 24 [2] 91 25 [2] 8a 23 [2] 96 24 [2] 8a 0b }

  condition:
    any of them
}