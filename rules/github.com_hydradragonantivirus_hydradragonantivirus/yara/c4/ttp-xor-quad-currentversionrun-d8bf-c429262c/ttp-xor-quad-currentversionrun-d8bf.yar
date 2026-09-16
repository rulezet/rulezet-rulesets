rule TTP_XOR_QUAD_CurrentVersionRun_d8bf {
  strings:
    $key_d8bf = { 8b d0 [2] af de [2] 84 f2 [2] aa d0 [2] be cb [2] b1 d1 [2] af cc [2] ad cd [2] b6 cb [2] aa cc [2] b6 e3 }

  condition:
    any of them
}