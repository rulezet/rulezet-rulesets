rule TTP_XOR_QUAD_CurrentVersionRun_a7a3 {
  strings:
    $key_a7a3 = { f4 cc [2] d0 c2 [2] fb ee [2] d5 cc [2] c1 d7 [2] ce cd [2] d0 d0 [2] d2 d1 [2] c9 d7 [2] d5 d0 [2] c9 ff }

  condition:
    any of them
}