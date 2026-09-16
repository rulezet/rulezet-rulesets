rule TTP_XOR_QUAD_CurrentVersionRun_f9ca {
  strings:
    $key_f9ca = { aa a5 [2] 8e ab [2] a5 87 [2] 8b a5 [2] 9f be [2] 90 a4 [2] 8e b9 [2] 8c b8 [2] 97 be [2] 8b b9 [2] 97 96 }

  condition:
    any of them
}