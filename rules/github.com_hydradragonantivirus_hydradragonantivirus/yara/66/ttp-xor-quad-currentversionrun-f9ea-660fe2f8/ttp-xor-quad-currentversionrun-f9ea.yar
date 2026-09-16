rule TTP_XOR_QUAD_CurrentVersionRun_f9ea {
  strings:
    $key_f9ea = { aa 85 [2] 8e 8b [2] a5 a7 [2] 8b 85 [2] 9f 9e [2] 90 84 [2] 8e 99 [2] 8c 98 [2] 97 9e [2] 8b 99 [2] 97 b6 }

  condition:
    any of them
}