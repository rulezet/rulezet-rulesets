rule TTP_XOR_QUAD_CurrentVersionRun_c2ea {
  strings:
    $key_c2ea = { 91 85 [2] b5 8b [2] 9e a7 [2] b0 85 [2] a4 9e [2] ab 84 [2] b5 99 [2] b7 98 [2] ac 9e [2] b0 99 [2] ac b6 }

  condition:
    any of them
}