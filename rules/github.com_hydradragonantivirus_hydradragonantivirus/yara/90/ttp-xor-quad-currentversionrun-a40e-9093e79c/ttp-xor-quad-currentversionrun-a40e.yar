rule TTP_XOR_QUAD_CurrentVersionRun_a40e {
  strings:
    $key_a40e = { f7 61 [2] d3 6f [2] f8 43 [2] d6 61 [2] c2 7a [2] cd 60 [2] d3 7d [2] d1 7c [2] ca 7a [2] d6 7d [2] ca 52 }

  condition:
    any of them
}