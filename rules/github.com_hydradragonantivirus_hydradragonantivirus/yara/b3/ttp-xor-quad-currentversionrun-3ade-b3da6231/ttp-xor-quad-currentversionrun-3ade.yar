rule TTP_XOR_QUAD_CurrentVersionRun_3ade {
  strings:
    $key_3ade = { 69 b1 [2] 4d bf [2] 66 93 [2] 48 b1 [2] 5c aa [2] 53 b0 [2] 4d ad [2] 4f ac [2] 54 aa [2] 48 ad [2] 54 82 }

  condition:
    any of them
}