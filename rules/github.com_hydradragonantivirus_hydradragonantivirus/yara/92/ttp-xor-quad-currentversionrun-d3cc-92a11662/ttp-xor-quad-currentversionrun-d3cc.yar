rule TTP_XOR_QUAD_CurrentVersionRun_d3cc {
  strings:
    $key_d3cc = { 80 a3 [2] a4 ad [2] 8f 81 [2] a1 a3 [2] b5 b8 [2] ba a2 [2] a4 bf [2] a6 be [2] bd b8 [2] a1 bf [2] bd 90 }

  condition:
    any of them
}