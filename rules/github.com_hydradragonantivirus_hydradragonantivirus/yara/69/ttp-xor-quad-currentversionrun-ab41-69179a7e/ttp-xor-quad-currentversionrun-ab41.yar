rule TTP_XOR_QUAD_CurrentVersionRun_ab41 {
  strings:
    $key_ab41 = { f8 2e [2] dc 20 [2] f7 0c [2] d9 2e [2] cd 35 [2] c2 2f [2] dc 32 [2] de 33 [2] c5 35 [2] d9 32 [2] c5 1d }

  condition:
    any of them
}