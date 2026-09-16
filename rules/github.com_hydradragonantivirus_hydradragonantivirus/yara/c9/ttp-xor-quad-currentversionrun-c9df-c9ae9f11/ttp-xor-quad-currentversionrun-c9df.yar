rule TTP_XOR_QUAD_CurrentVersionRun_c9df {
  strings:
    $key_c9df = { 9a b0 [2] be be [2] 95 92 [2] bb b0 [2] af ab [2] a0 b1 [2] be ac [2] bc ad [2] a7 ab [2] bb ac [2] a7 83 }

  condition:
    any of them
}