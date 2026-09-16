rule TTP_XOR_QUAD_CurrentVersionRun_e461 {
  strings:
    $key_e461 = { b7 0e [2] 93 00 [2] b8 2c [2] 96 0e [2] 82 15 [2] 8d 0f [2] 93 12 [2] 91 13 [2] 8a 15 [2] 96 12 [2] 8a 3d }

  condition:
    any of them
}