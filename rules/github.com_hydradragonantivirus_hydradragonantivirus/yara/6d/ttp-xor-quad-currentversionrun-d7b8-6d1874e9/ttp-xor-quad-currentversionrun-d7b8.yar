rule TTP_XOR_QUAD_CurrentVersionRun_d7b8 {
  strings:
    $key_d7b8 = { 84 d7 [2] a0 d9 [2] 8b f5 [2] a5 d7 [2] b1 cc [2] be d6 [2] a0 cb [2] a2 ca [2] b9 cc [2] a5 cb [2] b9 e4 }

  condition:
    any of them
}