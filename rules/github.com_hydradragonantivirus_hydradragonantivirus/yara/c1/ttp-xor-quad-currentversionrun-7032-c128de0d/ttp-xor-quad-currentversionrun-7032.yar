rule TTP_XOR_QUAD_CurrentVersionRun_7032 {
  strings:
    $key_7032 = { 23 5d [2] 07 53 [2] 2c 7f [2] 02 5d [2] 16 46 [2] 19 5c [2] 07 41 [2] 05 40 [2] 1e 46 [2] 02 41 [2] 1e 6e }

  condition:
    any of them
}