rule TTP_XOR_QUAD_CurrentVersionRun_ab4f {
  strings:
    $key_ab4f = { f8 20 [2] dc 2e [2] f7 02 [2] d9 20 [2] cd 3b [2] c2 21 [2] dc 3c [2] de 3d [2] c5 3b [2] d9 3c [2] c5 13 }

  condition:
    any of them
}