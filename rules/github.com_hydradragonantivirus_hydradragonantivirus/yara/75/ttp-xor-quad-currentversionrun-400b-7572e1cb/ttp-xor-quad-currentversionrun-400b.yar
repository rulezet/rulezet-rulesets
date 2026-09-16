rule TTP_XOR_QUAD_CurrentVersionRun_400b {
  strings:
    $key_400b = { 13 64 [2] 37 6a [2] 1c 46 [2] 32 64 [2] 26 7f [2] 29 65 [2] 37 78 [2] 35 79 [2] 2e 7f [2] 32 78 [2] 2e 57 }

  condition:
    any of them
}