rule TTP_XOR_QUAD_CurrentVersionRun_d2ba {
  strings:
    $key_d2ba = { 81 d5 [2] a5 db [2] 8e f7 [2] a0 d5 [2] b4 ce [2] bb d4 [2] a5 c9 [2] a7 c8 [2] bc ce [2] a0 c9 [2] bc e6 }

  condition:
    any of them
}