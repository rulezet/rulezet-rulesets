rule TTP_XOR_QUAD_CurrentVersionRun_664b {
  strings:
    $key_664b = { 35 24 [2] 11 2a [2] 3a 06 [2] 14 24 [2] 00 3f [2] 0f 25 [2] 11 38 [2] 13 39 [2] 08 3f [2] 14 38 [2] 08 17 }

  condition:
    any of them
}