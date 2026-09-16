rule TTP_XOR_QUAD_CurrentVersionRun_abf0 {
  strings:
    $key_abf0 = { f8 9f [2] dc 91 [2] f7 bd [2] d9 9f [2] cd 84 [2] c2 9e [2] dc 83 [2] de 82 [2] c5 84 [2] d9 83 [2] c5 ac }

  condition:
    any of them
}