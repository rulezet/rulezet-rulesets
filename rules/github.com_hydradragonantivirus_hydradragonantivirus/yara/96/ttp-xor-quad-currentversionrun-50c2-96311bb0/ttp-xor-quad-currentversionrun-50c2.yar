rule TTP_XOR_QUAD_CurrentVersionRun_50c2 {
  strings:
    $key_50c2 = { 03 ad [2] 27 a3 [2] 0c 8f [2] 22 ad [2] 36 b6 [2] 39 ac [2] 27 b1 [2] 25 b0 [2] 3e b6 [2] 22 b1 [2] 3e 9e }

  condition:
    any of them
}