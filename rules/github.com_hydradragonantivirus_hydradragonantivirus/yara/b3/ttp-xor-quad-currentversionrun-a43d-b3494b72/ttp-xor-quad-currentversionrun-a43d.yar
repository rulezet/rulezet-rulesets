rule TTP_XOR_QUAD_CurrentVersionRun_a43d {
  strings:
    $key_a43d = { f7 52 [2] d3 5c [2] f8 70 [2] d6 52 [2] c2 49 [2] cd 53 [2] d3 4e [2] d1 4f [2] ca 49 [2] d6 4e [2] ca 61 }

  condition:
    any of them
}