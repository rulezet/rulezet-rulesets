rule TTP_XOR_QUAD_CurrentVersionRun_e8df {
  strings:
    $key_e8df = { bb b0 [2] 9f be [2] b4 92 [2] 9a b0 [2] 8e ab [2] 81 b1 [2] 9f ac [2] 9d ad [2] 86 ab [2] 9a ac [2] 86 83 }

  condition:
    any of them
}