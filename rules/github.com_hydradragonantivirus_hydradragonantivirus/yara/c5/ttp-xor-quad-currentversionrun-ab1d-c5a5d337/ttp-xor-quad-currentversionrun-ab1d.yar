rule TTP_XOR_QUAD_CurrentVersionRun_ab1d {
  strings:
    $key_ab1d = { f8 72 [2] dc 7c [2] f7 50 [2] d9 72 [2] cd 69 [2] c2 73 [2] dc 6e [2] de 6f [2] c5 69 [2] d9 6e [2] c5 41 }

  condition:
    any of them
}