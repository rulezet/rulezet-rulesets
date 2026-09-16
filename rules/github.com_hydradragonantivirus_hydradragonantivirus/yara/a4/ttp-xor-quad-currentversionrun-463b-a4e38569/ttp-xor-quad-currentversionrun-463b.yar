rule TTP_XOR_QUAD_CurrentVersionRun_463b {
  strings:
    $key_463b = { 15 54 [2] 31 5a [2] 1a 76 [2] 34 54 [2] 20 4f [2] 2f 55 [2] 31 48 [2] 33 49 [2] 28 4f [2] 34 48 [2] 28 67 }

  condition:
    any of them
}