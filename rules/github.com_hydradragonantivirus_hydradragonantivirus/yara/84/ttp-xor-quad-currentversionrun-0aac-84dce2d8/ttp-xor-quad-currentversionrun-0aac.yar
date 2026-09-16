rule TTP_XOR_QUAD_CurrentVersionRun_0aac {
  strings:
    $key_0aac = { 59 c3 [2] 7d cd [2] 56 e1 [2] 78 c3 [2] 6c d8 [2] 63 c2 [2] 7d df [2] 7f de [2] 64 d8 [2] 78 df [2] 64 f0 }

  condition:
    any of them
}