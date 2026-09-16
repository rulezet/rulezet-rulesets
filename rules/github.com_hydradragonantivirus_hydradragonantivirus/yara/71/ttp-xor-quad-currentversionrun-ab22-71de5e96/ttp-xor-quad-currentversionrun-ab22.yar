rule TTP_XOR_QUAD_CurrentVersionRun_ab22 {
  strings:
    $key_ab22 = { f8 4d [2] dc 43 [2] f7 6f [2] d9 4d [2] cd 56 [2] c2 4c [2] dc 51 [2] de 50 [2] c5 56 [2] d9 51 [2] c5 7e }

  condition:
    any of them
}