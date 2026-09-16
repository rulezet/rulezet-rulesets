rule TTP_XOR_QUAD_CurrentVersionRun_dce6 {
  strings:
    $key_dce6 = { 8f 89 [2] ab 87 [2] 80 ab [2] ae 89 [2] ba 92 [2] b5 88 [2] ab 95 [2] a9 94 [2] b2 92 [2] ae 95 [2] b2 ba }

  condition:
    any of them
}