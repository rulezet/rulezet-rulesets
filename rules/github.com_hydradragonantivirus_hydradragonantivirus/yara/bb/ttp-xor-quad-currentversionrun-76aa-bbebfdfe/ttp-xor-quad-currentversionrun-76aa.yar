rule TTP_XOR_QUAD_CurrentVersionRun_76aa {
  strings:
    $key_76aa = { 25 c5 [2] 01 cb [2] 2a e7 [2] 04 c5 [2] 10 de [2] 1f c4 [2] 01 d9 [2] 03 d8 [2] 18 de [2] 04 d9 [2] 18 f6 }

  condition:
    any of them
}