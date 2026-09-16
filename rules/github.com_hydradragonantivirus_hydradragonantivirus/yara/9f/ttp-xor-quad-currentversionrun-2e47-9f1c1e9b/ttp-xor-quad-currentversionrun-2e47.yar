rule TTP_XOR_QUAD_CurrentVersionRun_2e47 {
  strings:
    $key_2e47 = { 7d 28 [2] 59 26 [2] 72 0a [2] 5c 28 [2] 48 33 [2] 47 29 [2] 59 34 [2] 5b 35 [2] 40 33 [2] 5c 34 [2] 40 1b }

  condition:
    any of them
}