rule TTP_XOR_QUAD_CurrentVersionRun_0b3b {
  strings:
    $key_0b3b = { 58 54 [2] 7c 5a [2] 57 76 [2] 79 54 [2] 6d 4f [2] 62 55 [2] 7c 48 [2] 7e 49 [2] 65 4f [2] 79 48 [2] 65 67 }

  condition:
    any of them
}