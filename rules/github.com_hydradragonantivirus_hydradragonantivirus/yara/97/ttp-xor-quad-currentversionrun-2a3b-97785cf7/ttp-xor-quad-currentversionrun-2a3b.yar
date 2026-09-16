rule TTP_XOR_QUAD_CurrentVersionRun_2a3b {
  strings:
    $key_2a3b = { 79 54 [2] 5d 5a [2] 76 76 [2] 58 54 [2] 4c 4f [2] 43 55 [2] 5d 48 [2] 5f 49 [2] 44 4f [2] 58 48 [2] 44 67 }

  condition:
    any of them
}