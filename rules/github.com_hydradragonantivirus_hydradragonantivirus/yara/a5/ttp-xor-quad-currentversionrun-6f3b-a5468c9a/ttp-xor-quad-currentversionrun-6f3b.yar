rule TTP_XOR_QUAD_CurrentVersionRun_6f3b {
  strings:
    $key_6f3b = { 3c 54 [2] 18 5a [2] 33 76 [2] 1d 54 [2] 09 4f [2] 06 55 [2] 18 48 [2] 1a 49 [2] 01 4f [2] 1d 48 [2] 01 67 }

  condition:
    any of them
}