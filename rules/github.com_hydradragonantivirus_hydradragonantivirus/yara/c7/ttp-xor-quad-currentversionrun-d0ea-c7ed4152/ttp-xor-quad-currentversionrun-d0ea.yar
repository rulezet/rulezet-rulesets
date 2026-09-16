rule TTP_XOR_QUAD_CurrentVersionRun_d0ea {
  strings:
    $key_d0ea = { 83 85 [2] a7 8b [2] 8c a7 [2] a2 85 [2] b6 9e [2] b9 84 [2] a7 99 [2] a5 98 [2] be 9e [2] a2 99 [2] be b6 }

  condition:
    any of them
}