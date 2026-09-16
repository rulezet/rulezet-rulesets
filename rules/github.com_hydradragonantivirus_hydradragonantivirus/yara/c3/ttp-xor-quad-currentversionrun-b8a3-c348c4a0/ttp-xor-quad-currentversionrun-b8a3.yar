rule TTP_XOR_QUAD_CurrentVersionRun_b8a3 {
  strings:
    $key_b8a3 = { eb cc [2] cf c2 [2] e4 ee [2] ca cc [2] de d7 [2] d1 cd [2] cf d0 [2] cd d1 [2] d6 d7 [2] ca d0 [2] d6 ff }

  condition:
    any of them
}