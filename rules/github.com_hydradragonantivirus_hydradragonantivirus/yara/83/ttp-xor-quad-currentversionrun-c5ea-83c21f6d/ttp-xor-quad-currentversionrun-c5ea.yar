rule TTP_XOR_QUAD_CurrentVersionRun_c5ea {
  strings:
    $key_c5ea = { 96 85 [2] b2 8b [2] 99 a7 [2] b7 85 [2] a3 9e [2] ac 84 [2] b2 99 [2] b0 98 [2] ab 9e [2] b7 99 [2] ab b6 }

  condition:
    any of them
}