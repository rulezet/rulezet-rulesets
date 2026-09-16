rule TTP_XOR_QUAD_CurrentVersionRun_2bea {
  strings:
    $key_2bea = { 78 85 [2] 5c 8b [2] 77 a7 [2] 59 85 [2] 4d 9e [2] 42 84 [2] 5c 99 [2] 5e 98 [2] 45 9e [2] 59 99 [2] 45 b6 }

  condition:
    any of them
}