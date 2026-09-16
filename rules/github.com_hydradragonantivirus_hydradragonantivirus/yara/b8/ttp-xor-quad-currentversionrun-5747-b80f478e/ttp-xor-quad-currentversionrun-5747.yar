rule TTP_XOR_QUAD_CurrentVersionRun_5747 {
  strings:
    $key_5747 = { 04 28 [2] 20 26 [2] 0b 0a [2] 25 28 [2] 31 33 [2] 3e 29 [2] 20 34 [2] 22 35 [2] 39 33 [2] 25 34 [2] 39 1b }

  condition:
    any of them
}