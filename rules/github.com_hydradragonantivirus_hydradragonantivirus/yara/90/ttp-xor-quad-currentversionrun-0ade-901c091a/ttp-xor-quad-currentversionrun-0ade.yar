rule TTP_XOR_QUAD_CurrentVersionRun_0ade {
  strings:
    $key_0ade = { 59 b1 [2] 7d bf [2] 56 93 [2] 78 b1 [2] 6c aa [2] 63 b0 [2] 7d ad [2] 7f ac [2] 64 aa [2] 78 ad [2] 64 82 }

  condition:
    any of them
}