rule TTP_XOR_QUAD_CurrentVersionRun_ab3c {
  strings:
    $key_ab3c = { f8 53 [2] dc 5d [2] f7 71 [2] d9 53 [2] cd 48 [2] c2 52 [2] dc 4f [2] de 4e [2] c5 48 [2] d9 4f [2] c5 60 }

  condition:
    any of them
}