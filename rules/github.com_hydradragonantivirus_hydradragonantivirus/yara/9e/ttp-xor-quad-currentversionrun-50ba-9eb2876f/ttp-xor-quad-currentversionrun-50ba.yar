rule TTP_XOR_QUAD_CurrentVersionRun_50ba {
  strings:
    $key_50ba = { 03 d5 [2] 27 db [2] 0c f7 [2] 22 d5 [2] 36 ce [2] 39 d4 [2] 27 c9 [2] 25 c8 [2] 3e ce [2] 22 c9 [2] 3e e6 }

  condition:
    any of them
}