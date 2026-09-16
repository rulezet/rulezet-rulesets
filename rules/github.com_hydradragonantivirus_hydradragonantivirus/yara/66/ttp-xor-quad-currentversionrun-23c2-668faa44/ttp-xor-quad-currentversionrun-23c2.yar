rule TTP_XOR_QUAD_CurrentVersionRun_23c2 {
  strings:
    $key_23c2 = { 70 ad [2] 54 a3 [2] 7f 8f [2] 51 ad [2] 45 b6 [2] 4a ac [2] 54 b1 [2] 56 b0 [2] 4d b6 [2] 51 b1 [2] 4d 9e }

  condition:
    any of them
}