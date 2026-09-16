rule TTP_XOR_QUAD_CurrentVersionRun_2ade {
  strings:
    $key_2ade = { 79 b1 [2] 5d bf [2] 76 93 [2] 58 b1 [2] 4c aa [2] 43 b0 [2] 5d ad [2] 5f ac [2] 44 aa [2] 58 ad [2] 44 82 }

  condition:
    any of them
}