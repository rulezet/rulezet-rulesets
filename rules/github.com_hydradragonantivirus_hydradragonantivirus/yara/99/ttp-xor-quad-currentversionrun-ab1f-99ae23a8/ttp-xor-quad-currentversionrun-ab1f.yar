rule TTP_XOR_QUAD_CurrentVersionRun_ab1f {
  strings:
    $key_ab1f = { f8 70 [2] dc 7e [2] f7 52 [2] d9 70 [2] cd 6b [2] c2 71 [2] dc 6c [2] de 6d [2] c5 6b [2] d9 6c [2] c5 43 }

  condition:
    any of them
}