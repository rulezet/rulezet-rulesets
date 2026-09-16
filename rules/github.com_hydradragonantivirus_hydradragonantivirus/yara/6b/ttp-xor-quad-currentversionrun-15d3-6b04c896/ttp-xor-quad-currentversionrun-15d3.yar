rule TTP_XOR_QUAD_CurrentVersionRun_15d3 {
  strings:
    $key_15d3 = { 46 bc [2] 62 b2 [2] 49 9e [2] 67 bc [2] 73 a7 [2] 7c bd [2] 62 a0 [2] 60 a1 [2] 7b a7 [2] 67 a0 [2] 7b 8f }

  condition:
    any of them
}