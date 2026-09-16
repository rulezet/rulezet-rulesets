rule TTP_XOR_QUAD_CurrentVersionRun_4227 {
  strings:
    $key_4227 = { 11 48 [2] 35 46 [2] 1e 6a [2] 30 48 [2] 24 53 [2] 2b 49 [2] 35 54 [2] 37 55 [2] 2c 53 [2] 30 54 [2] 2c 7b }

  condition:
    any of them
}