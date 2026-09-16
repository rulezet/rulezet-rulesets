rule TTP_XOR_QUAD_CurrentVersionRun_ab52 {
  strings:
    $key_ab52 = { f8 3d [2] dc 33 [2] f7 1f [2] d9 3d [2] cd 26 [2] c2 3c [2] dc 21 [2] de 20 [2] c5 26 [2] d9 21 [2] c5 0e }

  condition:
    any of them
}