rule TTP_XOR_QUAD_CurrentVersionRun_4c9d {
  strings:
    $key_4c9d = { 1f f2 [2] 3b fc [2] 10 d0 [2] 3e f2 [2] 2a e9 [2] 25 f3 [2] 3b ee [2] 39 ef [2] 22 e9 [2] 3e ee [2] 22 c1 }

  condition:
    any of them
}