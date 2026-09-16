rule TTP_XOR_QUAD_CurrentVersionRun_a48a {
  strings:
    $key_a48a = { f7 e5 [2] d3 eb [2] f8 c7 [2] d6 e5 [2] c2 fe [2] cd e4 [2] d3 f9 [2] d1 f8 [2] ca fe [2] d6 f9 [2] ca d6 }

  condition:
    any of them
}