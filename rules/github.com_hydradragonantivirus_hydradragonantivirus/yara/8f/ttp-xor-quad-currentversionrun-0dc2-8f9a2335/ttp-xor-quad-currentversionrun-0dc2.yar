rule TTP_XOR_QUAD_CurrentVersionRun_0dc2 {
  strings:
    $key_0dc2 = { 5e ad [2] 7a a3 [2] 51 8f [2] 7f ad [2] 6b b6 [2] 64 ac [2] 7a b1 [2] 78 b0 [2] 63 b6 [2] 7f b1 [2] 63 9e }

  condition:
    any of them
}