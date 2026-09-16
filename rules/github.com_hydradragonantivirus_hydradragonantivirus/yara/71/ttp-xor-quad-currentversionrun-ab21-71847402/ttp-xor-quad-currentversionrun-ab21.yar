rule TTP_XOR_QUAD_CurrentVersionRun_ab21 {
  strings:
    $key_ab21 = { f8 4e [2] dc 40 [2] f7 6c [2] d9 4e [2] cd 55 [2] c2 4f [2] dc 52 [2] de 53 [2] c5 55 [2] d9 52 [2] c5 7d }

  condition:
    any of them
}