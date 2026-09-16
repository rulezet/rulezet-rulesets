rule TTP_XOR_QUAD_CurrentVersionRun_ab32 {
  strings:
    $key_ab32 = { f8 5d [2] dc 53 [2] f7 7f [2] d9 5d [2] cd 46 [2] c2 5c [2] dc 41 [2] de 40 [2] c5 46 [2] d9 41 [2] c5 6e }

  condition:
    any of them
}