rule TTP_XOR_QUAD_CurrentVersionRun_e1c0 {
  strings:
    $key_e1c0 = { b2 af [2] 96 a1 [2] bd 8d [2] 93 af [2] 87 b4 [2] 88 ae [2] 96 b3 [2] 94 b2 [2] 8f b4 [2] 93 b3 [2] 8f 9c }

  condition:
    any of them
}