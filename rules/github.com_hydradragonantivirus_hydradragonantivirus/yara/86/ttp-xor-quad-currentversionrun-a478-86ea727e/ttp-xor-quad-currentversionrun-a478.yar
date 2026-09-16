rule TTP_XOR_QUAD_CurrentVersionRun_a478 {
  strings:
    $key_a478 = { f7 17 [2] d3 19 [2] f8 35 [2] d6 17 [2] c2 0c [2] cd 16 [2] d3 0b [2] d1 0a [2] ca 0c [2] d6 0b [2] ca 24 }

  condition:
    any of them
}