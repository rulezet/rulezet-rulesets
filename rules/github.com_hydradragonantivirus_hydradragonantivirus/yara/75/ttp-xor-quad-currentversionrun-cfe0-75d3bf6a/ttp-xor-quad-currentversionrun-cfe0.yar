rule TTP_XOR_QUAD_CurrentVersionRun_cfe0 {
  strings:
    $key_cfe0 = { 9c 8f [2] b8 81 [2] 93 ad [2] bd 8f [2] a9 94 [2] a6 8e [2] b8 93 [2] ba 92 [2] a1 94 [2] bd 93 [2] a1 bc }

  condition:
    any of them
}