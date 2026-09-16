rule TTP_XOR_QUAD_CurrentVersionRun_16b8 {
  strings:
    $key_16b8 = { 45 d7 [2] 61 d9 [2] 4a f5 [2] 64 d7 [2] 70 cc [2] 7f d6 [2] 61 cb [2] 63 ca [2] 78 cc [2] 64 cb [2] 78 e4 }

  condition:
    any of them
}