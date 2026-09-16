rule TTP_XOR_QUAD_CurrentVersionRun_c5ba {
  strings:
    $key_c5ba = { 96 d5 [2] b2 db [2] 99 f7 [2] b7 d5 [2] a3 ce [2] ac d4 [2] b2 c9 [2] b0 c8 [2] ab ce [2] b7 c9 [2] ab e6 }

  condition:
    any of them
}