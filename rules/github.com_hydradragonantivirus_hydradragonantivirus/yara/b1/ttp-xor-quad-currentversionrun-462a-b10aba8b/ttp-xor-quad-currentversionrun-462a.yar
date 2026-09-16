rule TTP_XOR_QUAD_CurrentVersionRun_462a {
  strings:
    $key_462a = { 15 45 [2] 31 4b [2] 1a 67 [2] 34 45 [2] 20 5e [2] 2f 44 [2] 31 59 [2] 33 58 [2] 28 5e [2] 34 59 [2] 28 76 }

  condition:
    any of them
}