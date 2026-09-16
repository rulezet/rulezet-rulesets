rule TTP_XOR_QUAD_CurrentVersionRun_19df {
  strings:
    $key_19df = { 4a b0 [2] 6e be [2] 45 92 [2] 6b b0 [2] 7f ab [2] 70 b1 [2] 6e ac [2] 6c ad [2] 77 ab [2] 6b ac [2] 77 83 }

  condition:
    any of them
}