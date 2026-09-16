rule TTP_XOR_QUAD_CurrentVersionRun_4c3b {
  strings:
    $key_4c3b = { 1f 54 [2] 3b 5a [2] 10 76 [2] 3e 54 [2] 2a 4f [2] 25 55 [2] 3b 48 [2] 39 49 [2] 22 4f [2] 3e 48 [2] 22 67 }

  condition:
    any of them
}