rule TTP_XOR_QUAD_CurrentVersionRun_29df {
  strings:
    $key_29df = { 7a b0 [2] 5e be [2] 75 92 [2] 5b b0 [2] 4f ab [2] 40 b1 [2] 5e ac [2] 5c ad [2] 47 ab [2] 5b ac [2] 47 83 }

  condition:
    any of them
}