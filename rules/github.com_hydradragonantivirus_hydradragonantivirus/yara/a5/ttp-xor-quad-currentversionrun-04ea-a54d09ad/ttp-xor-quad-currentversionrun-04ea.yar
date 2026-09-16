rule TTP_XOR_QUAD_CurrentVersionRun_04ea {
  strings:
    $key_04ea = { 57 85 [2] 73 8b [2] 58 a7 [2] 76 85 [2] 62 9e [2] 6d 84 [2] 73 99 [2] 71 98 [2] 6a 9e [2] 76 99 [2] 6a b6 }

  condition:
    any of them
}