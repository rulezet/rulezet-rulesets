rule TTP_XOR_QUAD_CurrentVersionRun_7e47 {
  strings:
    $key_7e47 = { 2d 28 [2] 09 26 [2] 22 0a [2] 0c 28 [2] 18 33 [2] 17 29 [2] 09 34 [2] 0b 35 [2] 10 33 [2] 0c 34 [2] 10 1b }

  condition:
    any of them
}