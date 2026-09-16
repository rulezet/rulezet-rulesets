rule TTP_XOR_QUAD_CurrentVersionRun_1c9d {
  strings:
    $key_1c9d = { 4f f2 [2] 6b fc [2] 40 d0 [2] 6e f2 [2] 7a e9 [2] 75 f3 [2] 6b ee [2] 69 ef [2] 72 e9 [2] 6e ee [2] 72 c1 }

  condition:
    any of them
}