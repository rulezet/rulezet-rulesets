rule TTP_XOR_QUAD_CurrentVersionRun_abfe {
  strings:
    $key_abfe = { f8 91 [2] dc 9f [2] f7 b3 [2] d9 91 [2] cd 8a [2] c2 90 [2] dc 8d [2] de 8c [2] c5 8a [2] d9 8d [2] c5 a2 }

  condition:
    any of them
}