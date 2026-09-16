rule TTP_XOR_QUAD_CurrentVersionRun_a48c {
  strings:
    $key_a48c = { f7 e3 [2] d3 ed [2] f8 c1 [2] d6 e3 [2] c2 f8 [2] cd e2 [2] d3 ff [2] d1 fe [2] ca f8 [2] d6 ff [2] ca d0 }

  condition:
    any of them
}