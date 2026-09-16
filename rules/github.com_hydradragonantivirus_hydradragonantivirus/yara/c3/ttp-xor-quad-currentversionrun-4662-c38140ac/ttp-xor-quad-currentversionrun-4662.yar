rule TTP_XOR_QUAD_CurrentVersionRun_4662 {
  strings:
    $key_4662 = { 15 0d [2] 31 03 [2] 1a 2f [2] 34 0d [2] 20 16 [2] 2f 0c [2] 31 11 [2] 33 10 [2] 28 16 [2] 34 11 [2] 28 3e }

  condition:
    any of them
}