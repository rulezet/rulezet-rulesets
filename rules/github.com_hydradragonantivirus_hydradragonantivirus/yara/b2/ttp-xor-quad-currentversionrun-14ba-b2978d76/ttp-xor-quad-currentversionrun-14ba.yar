rule TTP_XOR_QUAD_CurrentVersionRun_14ba {
  strings:
    $key_14ba = { 47 d5 [2] 63 db [2] 48 f7 [2] 66 d5 [2] 72 ce [2] 7d d4 [2] 63 c9 [2] 61 c8 [2] 7a ce [2] 66 c9 [2] 7a e6 }

  condition:
    any of them
}