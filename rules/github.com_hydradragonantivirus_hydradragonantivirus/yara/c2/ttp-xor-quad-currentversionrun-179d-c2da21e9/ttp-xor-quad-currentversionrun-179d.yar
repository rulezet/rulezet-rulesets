rule TTP_XOR_QUAD_CurrentVersionRun_179d {
  strings:
    $key_179d = { 44 f2 [2] 60 fc [2] 4b d0 [2] 65 f2 [2] 71 e9 [2] 7e f3 [2] 60 ee [2] 62 ef [2] 79 e9 [2] 65 ee [2] 79 c1 }

  condition:
    any of them
}