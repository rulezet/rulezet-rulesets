rule TTP_XOR_QUAD_CurrentVersionRun_e9ea {
  strings:
    $key_e9ea = { ba 85 [2] 9e 8b [2] b5 a7 [2] 9b 85 [2] 8f 9e [2] 80 84 [2] 9e 99 [2] 9c 98 [2] 87 9e [2] 9b 99 [2] 87 b6 }

  condition:
    any of them
}