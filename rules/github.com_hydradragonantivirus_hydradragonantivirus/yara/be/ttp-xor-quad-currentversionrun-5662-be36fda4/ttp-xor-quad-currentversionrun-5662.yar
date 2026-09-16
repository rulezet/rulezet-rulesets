rule TTP_XOR_QUAD_CurrentVersionRun_5662 {
  strings:
    $key_5662 = { 05 0d [2] 21 03 [2] 0a 2f [2] 24 0d [2] 30 16 [2] 3f 0c [2] 21 11 [2] 23 10 [2] 38 16 [2] 24 11 [2] 38 3e }

  condition:
    any of them
}