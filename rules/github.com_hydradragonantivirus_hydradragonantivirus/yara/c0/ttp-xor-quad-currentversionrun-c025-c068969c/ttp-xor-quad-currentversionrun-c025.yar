rule TTP_XOR_QUAD_CurrentVersionRun_c025 {
  strings:
    $key_c025 = { 93 4a [2] b7 44 [2] 9c 68 [2] b2 4a [2] a6 51 [2] a9 4b [2] b7 56 [2] b5 57 [2] ae 51 [2] b2 56 [2] ae 79 }

  condition:
    any of them
}