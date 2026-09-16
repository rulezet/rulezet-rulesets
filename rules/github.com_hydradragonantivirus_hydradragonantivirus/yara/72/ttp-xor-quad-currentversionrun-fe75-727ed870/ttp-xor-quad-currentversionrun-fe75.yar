rule TTP_XOR_QUAD_CurrentVersionRun_fe75 {
  strings:
    $key_fe75 = { ad 1a [2] 89 14 [2] a2 38 [2] 8c 1a [2] 98 01 [2] 97 1b [2] 89 06 [2] 8b 07 [2] 90 01 [2] 8c 06 [2] 90 29 }

  condition:
    any of them
}