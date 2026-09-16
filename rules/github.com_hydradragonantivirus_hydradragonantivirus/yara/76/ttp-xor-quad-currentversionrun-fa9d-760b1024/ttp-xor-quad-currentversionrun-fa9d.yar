rule TTP_XOR_QUAD_CurrentVersionRun_fa9d {
  strings:
    $key_fa9d = { a9 f2 [2] 8d fc [2] a6 d0 [2] 88 f2 [2] 9c e9 [2] 93 f3 [2] 8d ee [2] 8f ef [2] 94 e9 [2] 88 ee [2] 94 c1 }

  condition:
    any of them
}