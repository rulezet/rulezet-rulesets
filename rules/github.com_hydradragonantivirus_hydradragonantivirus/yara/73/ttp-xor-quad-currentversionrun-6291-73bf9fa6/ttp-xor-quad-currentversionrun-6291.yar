rule TTP_XOR_QUAD_CurrentVersionRun_6291 {
  strings:
    $key_6291 = { 31 fe [2] 15 f0 [2] 3e dc [2] 10 fe [2] 04 e5 [2] 0b ff [2] 15 e2 [2] 17 e3 [2] 0c e5 [2] 10 e2 [2] 0c cd }

  condition:
    any of them
}