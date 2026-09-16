rule TTP_XOR_QUAD_CurrentVersionRun_bc9d {
  strings:
    $key_bc9d = { ef f2 [2] cb fc [2] e0 d0 [2] ce f2 [2] da e9 [2] d5 f3 [2] cb ee [2] c9 ef [2] d2 e9 [2] ce ee [2] d2 c1 }

  condition:
    any of them
}