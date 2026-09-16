rule TTP_XOR_QUAD_CurrentVersionRun_01c2 {
  strings:
    $key_01c2 = { 52 ad [2] 76 a3 [2] 5d 8f [2] 73 ad [2] 67 b6 [2] 68 ac [2] 76 b1 [2] 74 b0 [2] 6f b6 [2] 73 b1 [2] 6f 9e }

  condition:
    any of them
}