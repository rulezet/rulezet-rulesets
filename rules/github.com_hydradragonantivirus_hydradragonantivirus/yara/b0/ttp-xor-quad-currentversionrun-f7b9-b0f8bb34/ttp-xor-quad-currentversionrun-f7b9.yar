rule TTP_XOR_QUAD_CurrentVersionRun_f7b9 {
  strings:
    $key_f7b9 = { a4 d6 [2] 80 d8 [2] ab f4 [2] 85 d6 [2] 91 cd [2] 9e d7 [2] 80 ca [2] 82 cb [2] 99 cd [2] 85 ca [2] 99 e5 }

  condition:
    any of them
}