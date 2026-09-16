rule TTP_XOR_QUAD_CurrentVersionRun_673b {
  strings:
    $key_673b = { 34 54 [2] 10 5a [2] 3b 76 [2] 15 54 [2] 01 4f [2] 0e 55 [2] 10 48 [2] 12 49 [2] 09 4f [2] 15 48 [2] 09 67 }

  condition:
    any of them
}