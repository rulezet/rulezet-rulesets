rule TTP_XOR_QUAD_CurrentVersionRun_ab2f {
  strings:
    $key_ab2f = { f8 40 [2] dc 4e [2] f7 62 [2] d9 40 [2] cd 5b [2] c2 41 [2] dc 5c [2] de 5d [2] c5 5b [2] d9 5c [2] c5 73 }

  condition:
    any of them
}