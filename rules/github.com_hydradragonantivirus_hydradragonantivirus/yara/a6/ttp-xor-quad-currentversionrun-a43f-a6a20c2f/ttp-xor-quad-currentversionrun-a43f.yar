rule TTP_XOR_QUAD_CurrentVersionRun_a43f {
  strings:
    $key_a43f = { f7 50 [2] d3 5e [2] f8 72 [2] d6 50 [2] c2 4b [2] cd 51 [2] d3 4c [2] d1 4d [2] ca 4b [2] d6 4c [2] ca 63 }

  condition:
    any of them
}