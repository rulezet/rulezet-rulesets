rule TTP_XOR_QUAD_CurrentVersionRun_7aac {
  strings:
    $key_7aac = { 29 c3 [2] 0d cd [2] 26 e1 [2] 08 c3 [2] 1c d8 [2] 13 c2 [2] 0d df [2] 0f de [2] 14 d8 [2] 08 df [2] 14 f0 }

  condition:
    any of them
}