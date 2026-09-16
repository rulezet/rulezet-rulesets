rule TTP_XOR_QUAD_CurrentVersionRun_caf1 {
  strings:
    $key_caf1 = { 99 9e [2] bd 90 [2] 96 bc [2] b8 9e [2] ac 85 [2] a3 9f [2] bd 82 [2] bf 83 [2] a4 85 [2] b8 82 [2] a4 ad }

  condition:
    any of them
}