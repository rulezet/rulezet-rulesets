rule TTP_XOR_QUAD_CurrentVersionRun_a4fe {
  strings:
    $key_a4fe = { f7 91 [2] d3 9f [2] f8 b3 [2] d6 91 [2] c2 8a [2] cd 90 [2] d3 8d [2] d1 8c [2] ca 8a [2] d6 8d [2] ca a2 }

  condition:
    any of them
}