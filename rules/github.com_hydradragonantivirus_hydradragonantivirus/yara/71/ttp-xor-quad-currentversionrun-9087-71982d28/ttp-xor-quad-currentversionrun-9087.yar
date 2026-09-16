rule TTP_XOR_QUAD_CurrentVersionRun_9087 {
  strings:
    $key_9087 = { c3 e8 [2] e7 e6 [2] cc ca [2] e2 e8 [2] f6 f3 [2] f9 e9 [2] e7 f4 [2] e5 f5 [2] fe f3 [2] e2 f4 [2] fe db }

  condition:
    any of them
}