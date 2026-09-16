rule TTP_XOR_QUAD_CurrentVersionRun_ab30 {
  strings:
    $key_ab30 = { f8 5f [2] dc 51 [2] f7 7d [2] d9 5f [2] cd 44 [2] c2 5e [2] dc 43 [2] de 42 [2] c5 44 [2] d9 43 [2] c5 6c }

  condition:
    any of them
}