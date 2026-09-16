rule TTP_XOR_QUAD_CurrentVersionRun_33c2 {
  strings:
    $key_33c2 = { 60 ad [2] 44 a3 [2] 6f 8f [2] 41 ad [2] 55 b6 [2] 5a ac [2] 44 b1 [2] 46 b0 [2] 5d b6 [2] 41 b1 [2] 5d 9e }

  condition:
    any of them
}