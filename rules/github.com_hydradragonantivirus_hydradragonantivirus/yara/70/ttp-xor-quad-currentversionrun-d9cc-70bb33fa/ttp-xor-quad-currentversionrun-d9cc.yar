rule TTP_XOR_QUAD_CurrentVersionRun_d9cc {
  strings:
    $key_d9cc = { 8a a3 [2] ae ad [2] 85 81 [2] ab a3 [2] bf b8 [2] b0 a2 [2] ae bf [2] ac be [2] b7 b8 [2] ab bf [2] b7 90 }

  condition:
    any of them
}