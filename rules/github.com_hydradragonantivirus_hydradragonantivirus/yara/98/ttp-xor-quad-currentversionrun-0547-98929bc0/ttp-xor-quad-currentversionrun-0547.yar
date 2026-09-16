rule TTP_XOR_QUAD_CurrentVersionRun_0547 {
  strings:
    $key_0547 = { 56 28 [2] 72 26 [2] 59 0a [2] 77 28 [2] 63 33 [2] 6c 29 [2] 72 34 [2] 70 35 [2] 6b 33 [2] 77 34 [2] 6b 1b }

  condition:
    any of them
}