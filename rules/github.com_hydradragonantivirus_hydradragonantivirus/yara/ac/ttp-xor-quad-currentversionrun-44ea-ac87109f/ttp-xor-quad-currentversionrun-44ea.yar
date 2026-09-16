rule TTP_XOR_QUAD_CurrentVersionRun_44ea {
  strings:
    $key_44ea = { 17 85 [2] 33 8b [2] 18 a7 [2] 36 85 [2] 22 9e [2] 2d 84 [2] 33 99 [2] 31 98 [2] 2a 9e [2] 36 99 [2] 2a b6 }

  condition:
    any of them
}