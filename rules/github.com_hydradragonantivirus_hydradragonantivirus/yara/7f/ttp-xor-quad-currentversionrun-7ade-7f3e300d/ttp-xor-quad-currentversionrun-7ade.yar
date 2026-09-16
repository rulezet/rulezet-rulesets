rule TTP_XOR_QUAD_CurrentVersionRun_7ade {
  strings:
    $key_7ade = { 29 b1 [2] 0d bf [2] 26 93 [2] 08 b1 [2] 1c aa [2] 13 b0 [2] 0d ad [2] 0f ac [2] 14 aa [2] 08 ad [2] 14 82 }

  condition:
    any of them
}