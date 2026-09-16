rule TTP_XOR_QUAD_CurrentVersionRun_14a5 {
  strings:
    $key_14a5 = { 47 ca [2] 63 c4 [2] 48 e8 [2] 66 ca [2] 72 d1 [2] 7d cb [2] 63 d6 [2] 61 d7 [2] 7a d1 [2] 66 d6 [2] 7a f9 }

  condition:
    any of them
}