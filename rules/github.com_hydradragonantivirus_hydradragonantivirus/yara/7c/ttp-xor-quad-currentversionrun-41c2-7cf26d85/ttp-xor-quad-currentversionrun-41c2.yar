rule TTP_XOR_QUAD_CurrentVersionRun_41c2 {
  strings:
    $key_41c2 = { 12 ad [2] 36 a3 [2] 1d 8f [2] 33 ad [2] 27 b6 [2] 28 ac [2] 36 b1 [2] 34 b0 [2] 2f b6 [2] 33 b1 [2] 2f 9e }

  condition:
    any of them
}