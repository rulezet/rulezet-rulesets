rule TTP_XOR_QUAD_CurrentVersionRun_5aac {
  strings:
    $key_5aac = { 09 c3 [2] 2d cd [2] 06 e1 [2] 28 c3 [2] 3c d8 [2] 33 c2 [2] 2d df [2] 2f de [2] 34 d8 [2] 28 df [2] 34 f0 }

  condition:
    any of them
}