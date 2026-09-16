rule TTP_XOR_QUAD_CurrentVersionRun_cecf {
  strings:
    $key_cecf = { 9d a0 [2] b9 ae [2] 92 82 [2] bc a0 [2] a8 bb [2] a7 a1 [2] b9 bc [2] bb bd [2] a0 bb [2] bc bc [2] a0 93 }

  condition:
    any of them
}