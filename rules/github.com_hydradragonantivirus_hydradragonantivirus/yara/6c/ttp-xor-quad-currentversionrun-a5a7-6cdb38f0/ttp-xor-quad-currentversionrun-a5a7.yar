rule TTP_XOR_QUAD_CurrentVersionRun_a5a7 {
  strings:
    $key_a5a7 = { f6 c8 [2] d2 c6 [2] f9 ea [2] d7 c8 [2] c3 d3 [2] cc c9 [2] d2 d4 [2] d0 d5 [2] cb d3 [2] d7 d4 [2] cb fb }

  condition:
    any of them
}