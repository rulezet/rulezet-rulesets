rule TTP_XOR_QUAD_CurrentVersionRun_cfa3 {
  strings:
    $key_cfa3 = { 9c cc [2] b8 c2 [2] 93 ee [2] bd cc [2] a9 d7 [2] a6 cd [2] b8 d0 [2] ba d1 [2] a1 d7 [2] bd d0 [2] a1 ff }

  condition:
    any of them
}