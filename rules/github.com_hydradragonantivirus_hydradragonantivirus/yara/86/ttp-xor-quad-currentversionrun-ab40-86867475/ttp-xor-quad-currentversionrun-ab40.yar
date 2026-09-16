rule TTP_XOR_QUAD_CurrentVersionRun_ab40 {
  strings:
    $key_ab40 = { f8 2f [2] dc 21 [2] f7 0d [2] d9 2f [2] cd 34 [2] c2 2e [2] dc 33 [2] de 32 [2] c5 34 [2] d9 33 [2] c5 1c }

  condition:
    any of them
}