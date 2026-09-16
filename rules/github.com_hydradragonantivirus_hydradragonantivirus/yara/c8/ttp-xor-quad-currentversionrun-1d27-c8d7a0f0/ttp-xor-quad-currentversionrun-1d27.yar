rule TTP_XOR_QUAD_CurrentVersionRun_1d27 {
  strings:
    $key_1d27 = { 4e 48 [2] 6a 46 [2] 41 6a [2] 6f 48 [2] 7b 53 [2] 74 49 [2] 6a 54 [2] 68 55 [2] 73 53 [2] 6f 54 [2] 73 7b }

  condition:
    any of them
}