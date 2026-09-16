rule TTP_XOR_QUAD_CurrentVersionRun_a43b {
  strings:
    $key_a43b = { f7 54 [2] d3 5a [2] f8 76 [2] d6 54 [2] c2 4f [2] cd 55 [2] d3 48 [2] d1 49 [2] ca 4f [2] d6 48 [2] ca 67 }

  condition:
    any of them
}