rule TTP_XOR_QUAD_CurrentVersionRun_7015 {
  strings:
    $key_7015 = { 23 7a [2] 07 74 [2] 2c 58 [2] 02 7a [2] 16 61 [2] 19 7b [2] 07 66 [2] 05 67 [2] 1e 61 [2] 02 66 [2] 1e 49 }

  condition:
    any of them
}