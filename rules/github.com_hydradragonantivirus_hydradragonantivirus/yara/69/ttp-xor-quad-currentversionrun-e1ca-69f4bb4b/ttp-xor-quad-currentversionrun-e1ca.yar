rule TTP_XOR_QUAD_CurrentVersionRun_e1ca {
  strings:
    $key_e1ca = { b2 a5 [2] 96 ab [2] bd 87 [2] 93 a5 [2] 87 be [2] 88 a4 [2] 96 b9 [2] 94 b8 [2] 8f be [2] 93 b9 [2] 8f 96 }

  condition:
    any of them
}