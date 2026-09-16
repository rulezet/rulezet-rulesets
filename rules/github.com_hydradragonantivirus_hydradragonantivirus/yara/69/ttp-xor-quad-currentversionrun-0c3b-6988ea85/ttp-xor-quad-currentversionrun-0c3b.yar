rule TTP_XOR_QUAD_CurrentVersionRun_0c3b {
  strings:
    $key_0c3b = { 5f 54 [2] 7b 5a [2] 50 76 [2] 7e 54 [2] 6a 4f [2] 65 55 [2] 7b 48 [2] 79 49 [2] 62 4f [2] 7e 48 [2] 62 67 }

  condition:
    any of them
}