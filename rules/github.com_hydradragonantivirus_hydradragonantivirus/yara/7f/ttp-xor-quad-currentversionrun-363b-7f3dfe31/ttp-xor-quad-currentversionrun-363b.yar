rule TTP_XOR_QUAD_CurrentVersionRun_363b {
  strings:
    $key_363b = { 65 54 [2] 41 5a [2] 6a 76 [2] 44 54 [2] 50 4f [2] 5f 55 [2] 41 48 [2] 43 49 [2] 58 4f [2] 44 48 [2] 58 67 }

  condition:
    any of them
}