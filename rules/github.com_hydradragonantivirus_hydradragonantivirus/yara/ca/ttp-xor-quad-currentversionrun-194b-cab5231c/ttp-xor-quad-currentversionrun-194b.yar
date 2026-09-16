rule TTP_XOR_QUAD_CurrentVersionRun_194b {
  strings:
    $key_194b = { 4a 24 [2] 6e 2a [2] 45 06 [2] 6b 24 [2] 7f 3f [2] 70 25 [2] 6e 38 [2] 6c 39 [2] 77 3f [2] 6b 38 [2] 77 17 }

  condition:
    any of them
}