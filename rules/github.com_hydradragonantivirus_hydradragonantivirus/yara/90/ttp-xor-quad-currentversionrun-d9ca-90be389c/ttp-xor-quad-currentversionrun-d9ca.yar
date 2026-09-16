rule TTP_XOR_QUAD_CurrentVersionRun_d9ca {
  strings:
    $key_d9ca = { 8a a5 [2] ae ab [2] 85 87 [2] ab a5 [2] bf be [2] b0 a4 [2] ae b9 [2] ac b8 [2] b7 be [2] ab b9 [2] b7 96 }

  condition:
    any of them
}