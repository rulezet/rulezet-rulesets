rule TTP_XOR_QUAD_CurrentVersionRun_36b9 {
  strings:
    $key_36b9 = { 65 d6 [2] 41 d8 [2] 6a f4 [2] 44 d6 [2] 50 cd [2] 5f d7 [2] 41 ca [2] 43 cb [2] 58 cd [2] 44 ca [2] 58 e5 }

  condition:
    any of them
}