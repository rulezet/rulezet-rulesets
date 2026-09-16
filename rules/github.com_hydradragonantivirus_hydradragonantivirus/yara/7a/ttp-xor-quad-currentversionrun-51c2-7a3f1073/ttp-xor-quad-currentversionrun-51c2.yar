rule TTP_XOR_QUAD_CurrentVersionRun_51c2 {
  strings:
    $key_51c2 = { 02 ad [2] 26 a3 [2] 0d 8f [2] 23 ad [2] 37 b6 [2] 38 ac [2] 26 b1 [2] 24 b0 [2] 3f b6 [2] 23 b1 [2] 3f 9e }

  condition:
    any of them
}