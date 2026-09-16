rule TTP_XOR_QUAD_CurrentVersionRun_1ade {
  strings:
    $key_1ade = { 49 b1 [2] 6d bf [2] 46 93 [2] 68 b1 [2] 7c aa [2] 73 b0 [2] 6d ad [2] 6f ac [2] 74 aa [2] 68 ad [2] 74 82 }

  condition:
    any of them
}