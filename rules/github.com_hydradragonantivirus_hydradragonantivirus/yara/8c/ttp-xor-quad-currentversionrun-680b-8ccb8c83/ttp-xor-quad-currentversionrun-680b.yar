rule TTP_XOR_QUAD_CurrentVersionRun_680b {
  strings:
    $key_680b = { 3b 64 [2] 1f 6a [2] 34 46 [2] 1a 64 [2] 0e 7f [2] 01 65 [2] 1f 78 [2] 1d 79 [2] 06 7f [2] 1a 78 [2] 06 57 }

  condition:
    any of them
}