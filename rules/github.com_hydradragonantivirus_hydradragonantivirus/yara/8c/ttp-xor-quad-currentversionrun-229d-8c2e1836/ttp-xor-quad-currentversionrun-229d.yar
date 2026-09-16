rule TTP_XOR_QUAD_CurrentVersionRun_229d {
  strings:
    $key_229d = { 71 f2 [2] 55 fc [2] 7e d0 [2] 50 f2 [2] 44 e9 [2] 4b f3 [2] 55 ee [2] 57 ef [2] 4c e9 [2] 50 ee [2] 4c c1 }

  condition:
    any of them
}