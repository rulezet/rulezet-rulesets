rule TTP_XOR_QUAD_CurrentVersionRun_f6b9 {
  strings:
    $key_f6b9 = { a5 d6 [2] 81 d8 [2] aa f4 [2] 84 d6 [2] 90 cd [2] 9f d7 [2] 81 ca [2] 83 cb [2] 98 cd [2] 84 ca [2] 98 e5 }

  condition:
    any of them
}