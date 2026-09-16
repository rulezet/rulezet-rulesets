rule TTP_XOR_QUAD_CurrentVersionRun_37b9 {
  strings:
    $key_37b9 = { 64 d6 [2] 40 d8 [2] 6b f4 [2] 45 d6 [2] 51 cd [2] 5e d7 [2] 40 ca [2] 42 cb [2] 59 cd [2] 45 ca [2] 59 e5 }

  condition:
    any of them
}