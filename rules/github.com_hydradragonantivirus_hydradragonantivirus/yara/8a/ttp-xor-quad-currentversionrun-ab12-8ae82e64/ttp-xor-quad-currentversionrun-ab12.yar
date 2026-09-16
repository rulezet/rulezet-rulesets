rule TTP_XOR_QUAD_CurrentVersionRun_ab12 {
  strings:
    $key_ab12 = { f8 7d [2] dc 73 [2] f7 5f [2] d9 7d [2] cd 66 [2] c2 7c [2] dc 61 [2] de 60 [2] c5 66 [2] d9 61 [2] c5 4e }

  condition:
    any of them
}