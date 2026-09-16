rule TTP_XOR_QUAD_CurrentVersionRun_e1c1 {
  strings:
    $key_e1c1 = { b2 ae [2] 96 a0 [2] bd 8c [2] 93 ae [2] 87 b5 [2] 88 af [2] 96 b2 [2] 94 b3 [2] 8f b5 [2] 93 b2 [2] 8f 9d }

  condition:
    any of them
}