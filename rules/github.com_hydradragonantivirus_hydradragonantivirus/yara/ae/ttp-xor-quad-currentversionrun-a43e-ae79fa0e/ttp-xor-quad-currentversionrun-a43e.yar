rule TTP_XOR_QUAD_CurrentVersionRun_a43e {
  strings:
    $key_a43e = { f7 51 [2] d3 5f [2] f8 73 [2] d6 51 [2] c2 4a [2] cd 50 [2] d3 4d [2] d1 4c [2] ca 4a [2] d6 4d [2] ca 62 }

  condition:
    any of them
}