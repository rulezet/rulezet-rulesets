rule TTP_XOR_QUAD_CurrentVersionRun_e1c2 {
  strings:
    $key_e1c2 = { b2 ad [2] 96 a3 [2] bd 8f [2] 93 ad [2] 87 b6 [2] 88 ac [2] 96 b1 [2] 94 b0 [2] 8f b6 [2] 93 b1 [2] 8f 9e }

  condition:
    any of them
}