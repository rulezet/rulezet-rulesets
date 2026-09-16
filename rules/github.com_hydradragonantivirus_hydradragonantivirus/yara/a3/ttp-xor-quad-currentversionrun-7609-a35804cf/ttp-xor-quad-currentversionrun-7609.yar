rule TTP_XOR_QUAD_CurrentVersionRun_7609 {
  strings:
    $key_7609 = { 25 66 [2] 01 68 [2] 2a 44 [2] 04 66 [2] 10 7d [2] 1f 67 [2] 01 7a [2] 03 7b [2] 18 7d [2] 04 7a [2] 18 55 }

  condition:
    any of them
}