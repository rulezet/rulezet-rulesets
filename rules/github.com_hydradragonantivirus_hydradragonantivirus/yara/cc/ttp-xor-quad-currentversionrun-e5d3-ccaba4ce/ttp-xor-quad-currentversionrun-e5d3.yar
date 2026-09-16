rule TTP_XOR_QUAD_CurrentVersionRun_e5d3 {
  strings:
    $key_e5d3 = { b6 bc [2] 92 b2 [2] b9 9e [2] 97 bc [2] 83 a7 [2] 8c bd [2] 92 a0 [2] 90 a1 [2] 8b a7 [2] 97 a0 [2] 8b 8f }

  condition:
    any of them
}