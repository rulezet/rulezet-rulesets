rule TTP_XOR_QUAD_CurrentVersionRun_43ea {
  strings:
    $key_43ea = { 10 85 [2] 34 8b [2] 1f a7 [2] 31 85 [2] 25 9e [2] 2a 84 [2] 34 99 [2] 36 98 [2] 2d 9e [2] 31 99 [2] 2d b6 }

  condition:
    any of them
}