rule TTP_XOR_QUAD_CurrentVersionRun_efea {
  strings:
    $key_efea = { bc 85 [2] 98 8b [2] b3 a7 [2] 9d 85 [2] 89 9e [2] 86 84 [2] 98 99 [2] 9a 98 [2] 81 9e [2] 9d 99 [2] 81 b6 }

  condition:
    any of them
}