rule TTP_XOR_QUAD_CurrentVersionRun_cae0 {
  strings:
    $key_cae0 = { 99 8f [2] bd 81 [2] 96 ad [2] b8 8f [2] ac 94 [2] a3 8e [2] bd 93 [2] bf 92 [2] a4 94 [2] b8 93 [2] a4 bc }

  condition:
    any of them
}