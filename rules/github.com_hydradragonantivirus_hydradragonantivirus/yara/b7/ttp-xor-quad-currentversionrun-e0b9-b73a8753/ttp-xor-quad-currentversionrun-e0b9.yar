rule TTP_XOR_QUAD_CurrentVersionRun_e0b9 {
  strings:
    $key_e0b9 = { b3 d6 [2] 97 d8 [2] bc f4 [2] 92 d6 [2] 86 cd [2] 89 d7 [2] 97 ca [2] 95 cb [2] 8e cd [2] 92 ca [2] 8e e5 }

  condition:
    any of them
}