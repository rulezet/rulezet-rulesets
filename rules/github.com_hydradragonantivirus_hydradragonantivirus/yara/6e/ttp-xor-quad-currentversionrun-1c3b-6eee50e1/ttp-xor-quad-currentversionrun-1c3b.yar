rule TTP_XOR_QUAD_CurrentVersionRun_1c3b {
  strings:
    $key_1c3b = { 4f 54 [2] 6b 5a [2] 40 76 [2] 6e 54 [2] 7a 4f [2] 75 55 [2] 6b 48 [2] 69 49 [2] 72 4f [2] 6e 48 [2] 72 67 }

  condition:
    any of them
}