rule TTP_XOR_QUAD_CurrentVersionRun_d9df {
  strings:
    $key_d9df = { 8a b0 [2] ae be [2] 85 92 [2] ab b0 [2] bf ab [2] b0 b1 [2] ae ac [2] ac ad [2] b7 ab [2] ab ac [2] b7 83 }

  condition:
    any of them
}