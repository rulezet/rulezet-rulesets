rule TTP_XOR_QUAD_CurrentVersionRun_7c9d {
  strings:
    $key_7c9d = { 2f f2 [2] 0b fc [2] 20 d0 [2] 0e f2 [2] 1a e9 [2] 15 f3 [2] 0b ee [2] 09 ef [2] 12 e9 [2] 0e ee [2] 12 c1 }

  condition:
    any of them
}