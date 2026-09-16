rule TTP_XOR_QUAD_CurrentVersionRun_d99c {
  strings:
    $key_d99c = { 8a f3 [2] ae fd [2] 85 d1 [2] ab f3 [2] bf e8 [2] b0 f2 [2] ae ef [2] ac ee [2] b7 e8 [2] ab ef [2] b7 c0 }

  condition:
    any of them
}