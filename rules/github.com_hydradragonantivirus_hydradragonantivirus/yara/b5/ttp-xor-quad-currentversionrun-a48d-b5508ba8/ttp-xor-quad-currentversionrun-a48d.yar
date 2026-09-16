rule TTP_XOR_QUAD_CurrentVersionRun_a48d {
  strings:
    $key_a48d = { f7 e2 [2] d3 ec [2] f8 c0 [2] d6 e2 [2] c2 f9 [2] cd e3 [2] d3 fe [2] d1 ff [2] ca f9 [2] d6 fe [2] ca d1 }

  condition:
    any of them
}