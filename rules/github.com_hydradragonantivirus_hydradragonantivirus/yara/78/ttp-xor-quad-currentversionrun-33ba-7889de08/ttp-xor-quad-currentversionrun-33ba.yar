rule TTP_XOR_QUAD_CurrentVersionRun_33ba {
  strings:
    $key_33ba = { 60 d5 [2] 44 db [2] 6f f7 [2] 41 d5 [2] 55 ce [2] 5a d4 [2] 44 c9 [2] 46 c8 [2] 5d ce [2] 41 c9 [2] 5d e6 }

  condition:
    any of them
}