rule TTP_XOR_QUAD_CurrentVersionRun_793b {
  strings:
    $key_793b = { 2a 54 [2] 0e 5a [2] 25 76 [2] 0b 54 [2] 1f 4f [2] 10 55 [2] 0e 48 [2] 0c 49 [2] 17 4f [2] 0b 48 [2] 17 67 }

  condition:
    any of them
}