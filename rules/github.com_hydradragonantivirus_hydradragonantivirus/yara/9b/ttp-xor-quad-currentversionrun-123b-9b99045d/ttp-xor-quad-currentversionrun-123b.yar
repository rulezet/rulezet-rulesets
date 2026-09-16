rule TTP_XOR_QUAD_CurrentVersionRun_123b {
  strings:
    $key_123b = { 41 54 [2] 65 5a [2] 4e 76 [2] 60 54 [2] 74 4f [2] 7b 55 [2] 65 48 [2] 67 49 [2] 7c 4f [2] 60 48 [2] 7c 67 }

  condition:
    any of them
}