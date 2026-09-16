rule TTP_XOR_QUAD_CurrentVersionRun_e1db {
  strings:
    $key_e1db = { b2 b4 [2] 96 ba [2] bd 96 [2] 93 b4 [2] 87 af [2] 88 b5 [2] 96 a8 [2] 94 a9 [2] 8f af [2] 93 a8 [2] 8f 87 }

  condition:
    any of them
}