rule TTP_XOR_QUAD_CurrentVersionRun_d4ea {
  strings:
    $key_d4ea = { 87 85 [2] a3 8b [2] 88 a7 [2] a6 85 [2] b2 9e [2] bd 84 [2] a3 99 [2] a1 98 [2] ba 9e [2] a6 99 [2] ba b6 }

  condition:
    any of them
}