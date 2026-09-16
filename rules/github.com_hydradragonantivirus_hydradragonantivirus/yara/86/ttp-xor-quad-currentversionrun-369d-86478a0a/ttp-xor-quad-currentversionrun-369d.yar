rule TTP_XOR_QUAD_CurrentVersionRun_369d {
  strings:
    $key_369d = { 65 f2 [2] 41 fc [2] 6a d0 [2] 44 f2 [2] 50 e9 [2] 5f f3 [2] 41 ee [2] 43 ef [2] 58 e9 [2] 44 ee [2] 58 c1 }

  condition:
    any of them
}