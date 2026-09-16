rule TTP_XOR_QUAD_CurrentVersionRun_abfc {
  strings:
    $key_abfc = { f8 93 [2] dc 9d [2] f7 b1 [2] d9 93 [2] cd 88 [2] c2 92 [2] dc 8f [2] de 8e [2] c5 88 [2] d9 8f [2] c5 a0 }

  condition:
    any of them
}