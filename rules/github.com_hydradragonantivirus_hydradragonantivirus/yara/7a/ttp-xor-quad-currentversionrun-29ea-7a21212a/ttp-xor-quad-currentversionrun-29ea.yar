rule TTP_XOR_QUAD_CurrentVersionRun_29ea {
  strings:
    $key_29ea = { 7a 85 [2] 5e 8b [2] 75 a7 [2] 5b 85 [2] 4f 9e [2] 40 84 [2] 5e 99 [2] 5c 98 [2] 47 9e [2] 5b 99 [2] 47 b6 }

  condition:
    any of them
}