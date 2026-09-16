rule TTP_XOR_QUAD_CurrentVersionRun_37ea {
  strings:
    $key_37ea = { 64 85 [2] 40 8b [2] 6b a7 [2] 45 85 [2] 51 9e [2] 5e 84 [2] 40 99 [2] 42 98 [2] 59 9e [2] 45 99 [2] 59 b6 }

  condition:
    any of them
}