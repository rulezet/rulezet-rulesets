rule TTP_XOR_QUAD_CurrentVersionRun_ab08 {
  strings:
    $key_ab08 = { f8 67 [2] dc 69 [2] f7 45 [2] d9 67 [2] cd 7c [2] c2 66 [2] dc 7b [2] de 7a [2] c5 7c [2] d9 7b [2] c5 54 }

  condition:
    any of them
}