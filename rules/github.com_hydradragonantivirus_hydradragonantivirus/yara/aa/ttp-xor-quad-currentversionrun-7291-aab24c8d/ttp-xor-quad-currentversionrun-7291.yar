rule TTP_XOR_QUAD_CurrentVersionRun_7291 {
  strings:
    $key_7291 = { 21 fe [2] 05 f0 [2] 2e dc [2] 00 fe [2] 14 e5 [2] 1b ff [2] 05 e2 [2] 07 e3 [2] 1c e5 [2] 00 e2 [2] 1c cd }

  condition:
    any of them
}