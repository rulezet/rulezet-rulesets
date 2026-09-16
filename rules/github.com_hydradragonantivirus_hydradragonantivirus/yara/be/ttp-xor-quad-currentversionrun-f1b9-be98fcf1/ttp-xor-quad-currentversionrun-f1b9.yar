rule TTP_XOR_QUAD_CurrentVersionRun_f1b9 {
  strings:
    $key_f1b9 = { a2 d6 [2] 86 d8 [2] ad f4 [2] 83 d6 [2] 97 cd [2] 98 d7 [2] 86 ca [2] 84 cb [2] 9f cd [2] 83 ca [2] 9f e5 }

  condition:
    any of them
}