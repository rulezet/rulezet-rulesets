rule TTP_XOR_QUAD_CurrentVersionRun_c0f6 {
  strings:
    $key_c0f6 = { 93 99 [2] b7 97 [2] 9c bb [2] b2 99 [2] a6 82 [2] a9 98 [2] b7 85 [2] b5 84 [2] ae 82 [2] b2 85 [2] ae aa }

  condition:
    any of them
}