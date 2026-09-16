rule TTP_XOR_QUAD_CurrentVersionRun_e19d {
  strings:
    $key_e19d = { b2 f2 [2] 96 fc [2] bd d0 [2] 93 f2 [2] 87 e9 [2] 88 f3 [2] 96 ee [2] 94 ef [2] 8f e9 [2] 93 ee [2] 8f c1 }

  condition:
    any of them
}