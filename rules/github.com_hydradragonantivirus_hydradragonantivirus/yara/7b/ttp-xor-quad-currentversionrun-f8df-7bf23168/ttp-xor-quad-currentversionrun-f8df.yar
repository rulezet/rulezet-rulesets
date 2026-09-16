rule TTP_XOR_QUAD_CurrentVersionRun_f8df {
  strings:
    $key_f8df = { ab b0 [2] 8f be [2] a4 92 [2] 8a b0 [2] 9e ab [2] 91 b1 [2] 8f ac [2] 8d ad [2] 96 ab [2] 8a ac [2] 96 83 }

  condition:
    any of them
}