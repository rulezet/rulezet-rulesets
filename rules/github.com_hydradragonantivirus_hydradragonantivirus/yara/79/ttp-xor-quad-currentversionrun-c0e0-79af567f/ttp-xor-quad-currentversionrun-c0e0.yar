rule TTP_XOR_QUAD_CurrentVersionRun_c0e0 {
  strings:
    $key_c0e0 = { 93 8f [2] b7 81 [2] 9c ad [2] b2 8f [2] a6 94 [2] a9 8e [2] b7 93 [2] b5 92 [2] ae 94 [2] b2 93 [2] ae bc }

  condition:
    any of them
}