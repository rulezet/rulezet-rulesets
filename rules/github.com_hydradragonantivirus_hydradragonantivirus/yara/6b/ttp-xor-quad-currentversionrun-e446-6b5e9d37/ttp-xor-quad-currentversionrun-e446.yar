rule TTP_XOR_QUAD_CurrentVersionRun_e446 {
  strings:
    $key_e446 = { b7 29 [2] 93 27 [2] b8 0b [2] 96 29 [2] 82 32 [2] 8d 28 [2] 93 35 [2] 91 34 [2] 8a 32 [2] 96 35 [2] 8a 1a }

  condition:
    any of them
}