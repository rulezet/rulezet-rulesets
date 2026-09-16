rule TTP_XOR_QUAD_CurrentVersionRun_e4ea {
  strings:
    $key_e4ea = { b7 85 [2] 93 8b [2] b8 a7 [2] 96 85 [2] 82 9e [2] 8d 84 [2] 93 99 [2] 91 98 [2] 8a 9e [2] 96 99 [2] 8a b6 }

  condition:
    any of them
}