rule TTP_XOR_QUAD_CurrentVersionRun_2c6b {
  strings:
    $key_2c6b = { 7f 04 [2] 5b 0a [2] 70 26 [2] 5e 04 [2] 4a 1f [2] 45 05 [2] 5b 18 [2] 59 19 [2] 42 1f [2] 5e 18 [2] 42 37 }

  condition:
    any of them
}