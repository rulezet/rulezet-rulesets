rule TTP_XOR_QUAD_CurrentVersionRun_faac {
  strings:
    $key_faac = { a9 c3 [2] 8d cd [2] a6 e1 [2] 88 c3 [2] 9c d8 [2] 93 c2 [2] 8d df [2] 8f de [2] 94 d8 [2] 88 df [2] 94 f0 }

  condition:
    any of them
}