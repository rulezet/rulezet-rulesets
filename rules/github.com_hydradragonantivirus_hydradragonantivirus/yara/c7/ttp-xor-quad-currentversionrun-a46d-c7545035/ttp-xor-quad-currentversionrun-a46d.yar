rule TTP_XOR_QUAD_CurrentVersionRun_a46d {
  strings:
    $key_a46d = { f7 02 [2] d3 0c [2] f8 20 [2] d6 02 [2] c2 19 [2] cd 03 [2] d3 1e [2] d1 1f [2] ca 19 [2] d6 1e [2] ca 31 }

  condition:
    any of them
}