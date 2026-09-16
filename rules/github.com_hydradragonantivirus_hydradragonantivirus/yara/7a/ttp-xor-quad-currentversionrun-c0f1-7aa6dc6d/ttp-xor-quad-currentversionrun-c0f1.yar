rule TTP_XOR_QUAD_CurrentVersionRun_c0f1 {
  strings:
    $key_c0f1 = { 93 9e [2] b7 90 [2] 9c bc [2] b2 9e [2] a6 85 [2] a9 9f [2] b7 82 [2] b5 83 [2] ae 85 [2] b2 82 [2] ae ad }

  condition:
    any of them
}