rule TTP_XOR_QUAD_CurrentVersionRun_190b {
  strings:
    $key_190b = { 4a 64 [2] 6e 6a [2] 45 46 [2] 6b 64 [2] 7f 7f [2] 70 65 [2] 6e 78 [2] 6c 79 [2] 77 7f [2] 6b 78 [2] 77 57 }

  condition:
    any of them
}