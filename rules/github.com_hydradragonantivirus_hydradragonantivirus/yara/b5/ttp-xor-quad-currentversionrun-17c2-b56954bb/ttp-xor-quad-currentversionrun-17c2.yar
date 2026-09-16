rule TTP_XOR_QUAD_CurrentVersionRun_17c2 {
  strings:
    $key_17c2 = { 44 ad [2] 60 a3 [2] 4b 8f [2] 65 ad [2] 71 b6 [2] 7e ac [2] 60 b1 [2] 62 b0 [2] 79 b6 [2] 65 b1 [2] 79 9e }

  condition:
    any of them
}