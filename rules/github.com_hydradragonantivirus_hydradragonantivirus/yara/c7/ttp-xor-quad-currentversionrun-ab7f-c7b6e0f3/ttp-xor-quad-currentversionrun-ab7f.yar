rule TTP_XOR_QUAD_CurrentVersionRun_ab7f {
  strings:
    $key_ab7f = { f8 10 [2] dc 1e [2] f7 32 [2] d9 10 [2] cd 0b [2] c2 11 [2] dc 0c [2] de 0d [2] c5 0b [2] d9 0c [2] c5 23 }

  condition:
    any of them
}