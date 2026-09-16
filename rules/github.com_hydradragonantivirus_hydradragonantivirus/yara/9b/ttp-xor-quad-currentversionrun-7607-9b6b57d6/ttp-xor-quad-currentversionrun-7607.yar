rule TTP_XOR_QUAD_CurrentVersionRun_7607 {
  strings:
    $key_7607 = { 25 68 [2] 01 66 [2] 2a 4a [2] 04 68 [2] 10 73 [2] 1f 69 [2] 01 74 [2] 03 75 [2] 18 73 [2] 04 74 [2] 18 5b }

  condition:
    any of them
}