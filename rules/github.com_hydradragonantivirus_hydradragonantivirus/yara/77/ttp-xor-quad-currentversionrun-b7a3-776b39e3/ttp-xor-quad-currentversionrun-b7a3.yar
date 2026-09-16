rule TTP_XOR_QUAD_CurrentVersionRun_b7a3 {
  strings:
    $key_b7a3 = { e4 cc [2] c0 c2 [2] eb ee [2] c5 cc [2] d1 d7 [2] de cd [2] c0 d0 [2] c2 d1 [2] d9 d7 [2] c5 d0 [2] d9 ff }

  condition:
    any of them
}