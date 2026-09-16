rule TTP_XOR_QUAD_CurrentVersionRun_f847 {
  strings:
    $key_f847 = { ab 28 [2] 8f 26 [2] a4 0a [2] 8a 28 [2] 9e 33 [2] 91 29 [2] 8f 34 [2] 8d 35 [2] 96 33 [2] 8a 34 [2] 96 1b }

  condition:
    any of them
}