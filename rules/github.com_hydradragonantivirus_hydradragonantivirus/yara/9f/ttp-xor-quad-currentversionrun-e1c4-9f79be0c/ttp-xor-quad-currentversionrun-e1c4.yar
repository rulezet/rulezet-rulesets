rule TTP_XOR_QUAD_CurrentVersionRun_e1c4 {
  strings:
    $key_e1c4 = { b2 ab [2] 96 a5 [2] bd 89 [2] 93 ab [2] 87 b0 [2] 88 aa [2] 96 b7 [2] 94 b6 [2] 8f b0 [2] 93 b7 [2] 8f 98 }

  condition:
    any of them
}