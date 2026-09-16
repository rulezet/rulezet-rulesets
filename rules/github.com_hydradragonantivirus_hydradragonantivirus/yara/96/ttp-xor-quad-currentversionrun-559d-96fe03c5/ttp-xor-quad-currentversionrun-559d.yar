rule TTP_XOR_QUAD_CurrentVersionRun_559d {
  strings:
    $key_559d = { 06 f2 [2] 22 fc [2] 09 d0 [2] 27 f2 [2] 33 e9 [2] 3c f3 [2] 22 ee [2] 20 ef [2] 3b e9 [2] 27 ee [2] 3b c1 }

  condition:
    any of them
}