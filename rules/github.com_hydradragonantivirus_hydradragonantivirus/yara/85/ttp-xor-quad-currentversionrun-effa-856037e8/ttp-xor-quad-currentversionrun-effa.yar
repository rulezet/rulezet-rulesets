rule TTP_XOR_QUAD_CurrentVersionRun_effa {
  strings:
    $key_effa = { bc 95 [2] 98 9b [2] b3 b7 [2] 9d 95 [2] 89 8e [2] 86 94 [2] 98 89 [2] 9a 88 [2] 81 8e [2] 9d 89 [2] 81 a6 }

  condition:
    any of them
}