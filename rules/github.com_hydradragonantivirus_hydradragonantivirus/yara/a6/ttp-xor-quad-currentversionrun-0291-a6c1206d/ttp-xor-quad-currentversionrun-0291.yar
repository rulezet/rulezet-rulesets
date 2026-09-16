rule TTP_XOR_QUAD_CurrentVersionRun_0291 {
  strings:
    $key_0291 = { 51 fe [2] 75 f0 [2] 5e dc [2] 70 fe [2] 64 e5 [2] 6b ff [2] 75 e2 [2] 77 e3 [2] 6c e5 [2] 70 e2 [2] 6c cd }

  condition:
    any of them
}