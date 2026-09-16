rule TTP_XOR_QUAD_CurrentVersionRun_38ea {
  strings:
    $key_38ea = { 6b 85 [2] 4f 8b [2] 64 a7 [2] 4a 85 [2] 5e 9e [2] 51 84 [2] 4f 99 [2] 4d 98 [2] 56 9e [2] 4a 99 [2] 56 b6 }

  condition:
    any of them
}