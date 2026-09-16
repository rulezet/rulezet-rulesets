rule TTP_XOR_QUAD_CurrentVersionRun_d8ba {
  strings:
    $key_d8ba = { 8b d5 [2] af db [2] 84 f7 [2] aa d5 [2] be ce [2] b1 d4 [2] af c9 [2] ad c8 [2] b6 ce [2] aa c9 [2] b6 e6 }

  condition:
    any of them
}