rule TTP_XOR_QUAD_CurrentVersionRun_b7a2 {
  strings:
    $key_b7a2 = { e4 cd [2] c0 c3 [2] eb ef [2] c5 cd [2] d1 d6 [2] de cc [2] c0 d1 [2] c2 d0 [2] d9 d6 [2] c5 d1 [2] d9 fe }

  condition:
    any of them
}