rule TTP_XOR_QUAD_CurrentVersionRun_51ba {
  strings:
    $key_51ba = { 02 d5 [2] 26 db [2] 0d f7 [2] 23 d5 [2] 37 ce [2] 38 d4 [2] 26 c9 [2] 24 c8 [2] 3f ce [2] 23 c9 [2] 3f e6 }

  condition:
    any of them
}