rule TTP_XOR_QUAD_CurrentVersionRun_2747 {
  strings:
    $key_2747 = { 74 28 [2] 50 26 [2] 7b 0a [2] 55 28 [2] 41 33 [2] 4e 29 [2] 50 34 [2] 52 35 [2] 49 33 [2] 55 34 [2] 49 1b }

  condition:
    any of them
}