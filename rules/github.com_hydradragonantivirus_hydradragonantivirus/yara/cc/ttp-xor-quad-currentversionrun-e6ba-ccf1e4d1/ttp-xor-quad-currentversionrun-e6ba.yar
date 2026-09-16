rule TTP_XOR_QUAD_CurrentVersionRun_e6ba {
  strings:
    $key_e6ba = { b5 d5 [2] 91 db [2] ba f7 [2] 94 d5 [2] 80 ce [2] 8f d4 [2] 91 c9 [2] 93 c8 [2] 88 ce [2] 94 c9 [2] 88 e6 }

  condition:
    any of them
}