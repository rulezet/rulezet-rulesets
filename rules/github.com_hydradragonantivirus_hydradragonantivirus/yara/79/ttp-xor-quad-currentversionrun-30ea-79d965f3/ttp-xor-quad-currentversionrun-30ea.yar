rule TTP_XOR_QUAD_CurrentVersionRun_30ea {
  strings:
    $key_30ea = { 63 85 [2] 47 8b [2] 6c a7 [2] 42 85 [2] 56 9e [2] 59 84 [2] 47 99 [2] 45 98 [2] 5e 9e [2] 42 99 [2] 5e b6 }

  condition:
    any of them
}