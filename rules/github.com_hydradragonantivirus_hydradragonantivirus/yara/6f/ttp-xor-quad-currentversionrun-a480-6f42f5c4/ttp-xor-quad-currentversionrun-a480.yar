rule TTP_XOR_QUAD_CurrentVersionRun_a480 {
  strings:
    $key_a480 = { f7 ef [2] d3 e1 [2] f8 cd [2] d6 ef [2] c2 f4 [2] cd ee [2] d3 f3 [2] d1 f2 [2] ca f4 [2] d6 f3 [2] ca dc }

  condition:
    any of them
}