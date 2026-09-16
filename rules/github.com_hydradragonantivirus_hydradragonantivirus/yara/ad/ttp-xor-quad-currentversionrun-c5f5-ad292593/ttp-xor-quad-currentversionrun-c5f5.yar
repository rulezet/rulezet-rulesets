rule TTP_XOR_QUAD_CurrentVersionRun_c5f5 {
  strings:
    $key_c5f5 = { 96 9a [2] b2 94 [2] 99 b8 [2] b7 9a [2] a3 81 [2] ac 9b [2] b2 86 [2] b0 87 [2] ab 81 [2] b7 86 [2] ab a9 }

  condition:
    any of them
}