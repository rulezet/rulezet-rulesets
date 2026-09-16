rule TTP_XOR_QUAD_CurrentVersionRun_3f87 {
  strings:
    $key_3f87 = { 6c e8 [2] 48 e6 [2] 63 ca [2] 4d e8 [2] 59 f3 [2] 56 e9 [2] 48 f4 [2] 4a f5 [2] 51 f3 [2] 4d f4 [2] 51 db }

  condition:
    any of them
}