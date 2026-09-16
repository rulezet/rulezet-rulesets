rule TTP_XOR_QUAD_CurrentVersionRun_eaac {
  strings:
    $key_eaac = { b9 c3 [2] 9d cd [2] b6 e1 [2] 98 c3 [2] 8c d8 [2] 83 c2 [2] 9d df [2] 9f de [2] 84 d8 [2] 98 df [2] 84 f0 }

  condition:
    any of them
}