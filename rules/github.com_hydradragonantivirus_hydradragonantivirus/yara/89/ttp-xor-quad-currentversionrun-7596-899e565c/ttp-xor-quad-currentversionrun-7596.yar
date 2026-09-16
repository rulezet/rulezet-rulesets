rule TTP_XOR_QUAD_CurrentVersionRun_7596 {
  strings:
    $key_7596 = { 26 f9 [2] 02 f7 [2] 29 db [2] 07 f9 [2] 13 e2 [2] 1c f8 [2] 02 e5 [2] 00 e4 [2] 1b e2 [2] 07 e5 [2] 1b ca }

  condition:
    any of them
}