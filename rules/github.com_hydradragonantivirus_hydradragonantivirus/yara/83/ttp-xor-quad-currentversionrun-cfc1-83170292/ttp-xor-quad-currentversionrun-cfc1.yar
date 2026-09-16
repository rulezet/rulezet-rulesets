rule TTP_XOR_QUAD_CurrentVersionRun_cfc1 {
  strings:
    $key_cfc1 = { 9c ae [2] b8 a0 [2] 93 8c [2] bd ae [2] a9 b5 [2] a6 af [2] b8 b2 [2] ba b3 [2] a1 b5 [2] bd b2 [2] a1 9d }

  condition:
    any of them
}