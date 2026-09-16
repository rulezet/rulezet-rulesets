rule TTP_XOR_QUAD_CurrentVersionRun_170b {
  strings:
    $key_170b = { 44 64 [2] 60 6a [2] 4b 46 [2] 65 64 [2] 71 7f [2] 7e 65 [2] 60 78 [2] 62 79 [2] 79 7f [2] 65 78 [2] 79 57 }

  condition:
    any of them
}