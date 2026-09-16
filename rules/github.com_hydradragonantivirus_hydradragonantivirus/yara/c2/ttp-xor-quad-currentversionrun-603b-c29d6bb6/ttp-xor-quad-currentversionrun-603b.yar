rule TTP_XOR_QUAD_CurrentVersionRun_603b {
  strings:
    $key_603b = { 33 54 [2] 17 5a [2] 3c 76 [2] 12 54 [2] 06 4f [2] 09 55 [2] 17 48 [2] 15 49 [2] 0e 4f [2] 12 48 [2] 0e 67 }

  condition:
    any of them
}