rule TTP_XOR_QUAD_CurrentVersionRun_35ba {
  strings:
    $key_35ba = { 66 d5 [2] 42 db [2] 69 f7 [2] 47 d5 [2] 53 ce [2] 5c d4 [2] 42 c9 [2] 40 c8 [2] 5b ce [2] 47 c9 [2] 5b e6 }

  condition:
    any of them
}