rule TTP_XOR_QUAD_CurrentVersionRun_ab1c {
  strings:
    $key_ab1c = { f8 73 [2] dc 7d [2] f7 51 [2] d9 73 [2] cd 68 [2] c2 72 [2] dc 6f [2] de 6e [2] c5 68 [2] d9 6f [2] c5 40 }

  condition:
    any of them
}