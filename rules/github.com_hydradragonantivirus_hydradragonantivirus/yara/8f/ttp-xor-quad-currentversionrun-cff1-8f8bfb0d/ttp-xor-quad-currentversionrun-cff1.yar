rule TTP_XOR_QUAD_CurrentVersionRun_cff1 {
  strings:
    $key_cff1 = { 9c 9e [2] b8 90 [2] 93 bc [2] bd 9e [2] a9 85 [2] a6 9f [2] b8 82 [2] ba 83 [2] a1 85 [2] bd 82 [2] a1 ad }

  condition:
    any of them
}