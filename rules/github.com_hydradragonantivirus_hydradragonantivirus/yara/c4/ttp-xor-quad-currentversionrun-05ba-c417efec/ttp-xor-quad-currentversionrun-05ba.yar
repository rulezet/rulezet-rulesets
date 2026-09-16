rule TTP_XOR_QUAD_CurrentVersionRun_05ba {
  strings:
    $key_05ba = { 56 d5 [2] 72 db [2] 59 f7 [2] 77 d5 [2] 63 ce [2] 6c d4 [2] 72 c9 [2] 70 c8 [2] 6b ce [2] 77 c9 [2] 6b e6 }

  condition:
    any of them
}