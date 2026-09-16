rule TTP_XOR_QUAD_CurrentVersionRun_57b8 {
  strings:
    $key_57b8 = { 04 d7 [2] 20 d9 [2] 0b f5 [2] 25 d7 [2] 31 cc [2] 3e d6 [2] 20 cb [2] 22 ca [2] 39 cc [2] 25 cb [2] 39 e4 }

  condition:
    any of them
}