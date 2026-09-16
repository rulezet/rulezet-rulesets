rule TTP_XOR_QUAD_CurrentVersionRun_e49d {
  strings:
    $key_e49d = { b7 f2 [2] 93 fc [2] b8 d0 [2] 96 f2 [2] 82 e9 [2] 8d f3 [2] 93 ee [2] 91 ef [2] 8a e9 [2] 96 ee [2] 8a c1 }

  condition:
    any of them
}