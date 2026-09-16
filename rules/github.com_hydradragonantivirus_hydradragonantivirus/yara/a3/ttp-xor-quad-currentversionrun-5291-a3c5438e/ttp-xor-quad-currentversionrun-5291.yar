rule TTP_XOR_QUAD_CurrentVersionRun_5291 {
  strings:
    $key_5291 = { 01 fe [2] 25 f0 [2] 0e dc [2] 20 fe [2] 34 e5 [2] 3b ff [2] 25 e2 [2] 27 e3 [2] 3c e5 [2] 20 e2 [2] 3c cd }

  condition:
    any of them
}