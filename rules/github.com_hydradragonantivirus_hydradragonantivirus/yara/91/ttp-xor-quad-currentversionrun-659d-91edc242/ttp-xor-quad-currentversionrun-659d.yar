rule TTP_XOR_QUAD_CurrentVersionRun_659d {
  strings:
    $key_659d = { 36 f2 [2] 12 fc [2] 39 d0 [2] 17 f2 [2] 03 e9 [2] 0c f3 [2] 12 ee [2] 10 ef [2] 0b e9 [2] 17 ee [2] 0b c1 }

  condition:
    any of them
}