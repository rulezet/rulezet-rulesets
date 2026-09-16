rule TTP_XOR_QUAD_CurrentVersionRun_d09d {
  strings:
    $key_d09d = { 83 f2 [2] a7 fc [2] 8c d0 [2] a2 f2 [2] b6 e9 [2] b9 f3 [2] a7 ee [2] a5 ef [2] be e9 [2] a2 ee [2] be c1 }

  condition:
    any of them
}