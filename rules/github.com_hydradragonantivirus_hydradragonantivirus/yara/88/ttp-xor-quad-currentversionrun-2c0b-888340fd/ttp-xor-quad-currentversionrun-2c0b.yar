rule TTP_XOR_QUAD_CurrentVersionRun_2c0b {
  strings:
    $key_2c0b = { 7f 64 [2] 5b 6a [2] 70 46 [2] 5e 64 [2] 4a 7f [2] 45 65 [2] 5b 78 [2] 59 79 [2] 42 7f [2] 5e 78 [2] 42 57 }

  condition:
    any of them
}