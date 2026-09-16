rule TTP_XOR_QUAD_CurrentVersionRun_ab0f {
  strings:
    $key_ab0f = { f8 60 [2] dc 6e [2] f7 42 [2] d9 60 [2] cd 7b [2] c2 61 [2] dc 7c [2] de 7d [2] c5 7b [2] d9 7c [2] c5 53 }

  condition:
    any of them
}