rule TTP_XOR_QUAD_CurrentVersionRun_06ba {
  strings:
    $key_06ba = { 55 d5 [2] 71 db [2] 5a f7 [2] 74 d5 [2] 60 ce [2] 6f d4 [2] 71 c9 [2] 73 c8 [2] 68 ce [2] 74 c9 [2] 68 e6 }

  condition:
    any of them
}