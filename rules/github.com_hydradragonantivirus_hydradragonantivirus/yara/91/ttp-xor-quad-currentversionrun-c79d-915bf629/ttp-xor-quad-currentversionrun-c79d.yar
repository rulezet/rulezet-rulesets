rule TTP_XOR_QUAD_CurrentVersionRun_c79d {
  strings:
    $key_c79d = { 94 f2 [2] b0 fc [2] 9b d0 [2] b5 f2 [2] a1 e9 [2] ae f3 [2] b0 ee [2] b2 ef [2] a9 e9 [2] b5 ee [2] a9 c1 }

  condition:
    any of them
}