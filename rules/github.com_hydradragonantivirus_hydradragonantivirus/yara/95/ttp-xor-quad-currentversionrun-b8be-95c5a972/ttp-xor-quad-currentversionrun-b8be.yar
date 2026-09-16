rule TTP_XOR_QUAD_CurrentVersionRun_b8be {
  strings:
    $key_b8be = { eb d1 [2] cf df [2] e4 f3 [2] ca d1 [2] de ca [2] d1 d0 [2] cf cd [2] cd cc [2] d6 ca [2] ca cd [2] d6 e2 }

  condition:
    any of them
}