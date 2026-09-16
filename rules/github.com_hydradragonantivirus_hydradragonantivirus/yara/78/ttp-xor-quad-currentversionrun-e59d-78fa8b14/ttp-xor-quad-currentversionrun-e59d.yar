rule TTP_XOR_QUAD_CurrentVersionRun_e59d {
  strings:
    $key_e59d = { b6 f2 [2] 92 fc [2] b9 d0 [2] 97 f2 [2] 83 e9 [2] 8c f3 [2] 92 ee [2] 90 ef [2] 8b e9 [2] 97 ee [2] 8b c1 }

  condition:
    any of them
}