rule TTP_XOR_QUAD_CurrentVersionRun_553b {
  strings:
    $key_553b = { 06 54 [2] 22 5a [2] 09 76 [2] 27 54 [2] 33 4f [2] 3c 55 [2] 22 48 [2] 20 49 [2] 3b 4f [2] 27 48 [2] 3b 67 }

  condition:
    any of them
}