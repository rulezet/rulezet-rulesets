rule TTP_XOR_QUAD_CurrentVersionRun_1e3b {
  strings:
    $key_1e3b = { 4d 54 [2] 69 5a [2] 42 76 [2] 6c 54 [2] 78 4f [2] 77 55 [2] 69 48 [2] 6b 49 [2] 70 4f [2] 6c 48 [2] 70 67 }

  condition:
    any of them
}