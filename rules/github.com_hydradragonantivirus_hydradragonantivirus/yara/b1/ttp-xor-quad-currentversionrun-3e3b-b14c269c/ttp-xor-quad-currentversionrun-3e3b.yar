rule TTP_XOR_QUAD_CurrentVersionRun_3e3b {
  strings:
    $key_3e3b = { 6d 54 [2] 49 5a [2] 62 76 [2] 4c 54 [2] 58 4f [2] 57 55 [2] 49 48 [2] 4b 49 [2] 50 4f [2] 4c 48 [2] 50 67 }

  condition:
    any of them
}