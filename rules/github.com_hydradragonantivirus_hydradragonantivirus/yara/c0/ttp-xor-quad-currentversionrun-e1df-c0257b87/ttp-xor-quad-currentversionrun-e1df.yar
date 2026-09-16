rule TTP_XOR_QUAD_CurrentVersionRun_e1df {
  strings:
    $key_e1df = { b2 b0 [2] 96 be [2] bd 92 [2] 93 b0 [2] 87 ab [2] 88 b1 [2] 96 ac [2] 94 ad [2] 8f ab [2] 93 ac [2] 8f 83 }

  condition:
    any of them
}