rule TTP_XOR_QUAD_CurrentVersionRun_5d3b {
  strings:
    $key_5d3b = { 0e 54 [2] 2a 5a [2] 01 76 [2] 2f 54 [2] 3b 4f [2] 34 55 [2] 2a 48 [2] 28 49 [2] 33 4f [2] 2f 48 [2] 33 67 }

  condition:
    any of them
}