rule TTP_XOR_QUAD_CurrentVersionRun_e0ea {
  strings:
    $key_e0ea = { b3 85 [2] 97 8b [2] bc a7 [2] 92 85 [2] 86 9e [2] 89 84 [2] 97 99 [2] 95 98 [2] 8e 9e [2] 92 99 [2] 8e b6 }

  condition:
    any of them
}