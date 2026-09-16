rule TTP_XOR_QUAD_CurrentVersionRun_193b {
  strings:
    $key_193b = { 4a 54 [2] 6e 5a [2] 45 76 [2] 6b 54 [2] 7f 4f [2] 70 55 [2] 6e 48 [2] 6c 49 [2] 77 4f [2] 6b 48 [2] 77 67 }

  condition:
    any of them
}