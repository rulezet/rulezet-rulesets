rule TTP_XOR_QUAD_CurrentVersionRun_73c2 {
  strings:
    $key_73c2 = { 20 ad [2] 04 a3 [2] 2f 8f [2] 01 ad [2] 15 b6 [2] 1a ac [2] 04 b1 [2] 06 b0 [2] 1d b6 [2] 01 b1 [2] 1d 9e }

  condition:
    any of them
}