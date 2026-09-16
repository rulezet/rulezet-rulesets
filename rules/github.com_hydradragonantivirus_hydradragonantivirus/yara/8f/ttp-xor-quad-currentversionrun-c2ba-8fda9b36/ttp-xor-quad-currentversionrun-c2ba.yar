rule TTP_XOR_QUAD_CurrentVersionRun_c2ba {
  strings:
    $key_c2ba = { 91 d5 [2] b5 db [2] 9e f7 [2] b0 d5 [2] a4 ce [2] ab d4 [2] b5 c9 [2] b7 c8 [2] ac ce [2] b0 c9 [2] ac e6 }

  condition:
    any of them
}