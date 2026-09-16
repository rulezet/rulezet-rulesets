rule TTP_XOR_QUAD_CurrentVersionRun_e2ea {
  strings:
    $key_e2ea = { b1 85 [2] 95 8b [2] be a7 [2] 90 85 [2] 84 9e [2] 8b 84 [2] 95 99 [2] 97 98 [2] 8c 9e [2] 90 99 [2] 8c b6 }

  condition:
    any of them
}