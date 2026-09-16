rule TTP_XOR_QUAD_CurrentVersionRun_51af {
  strings:
    $key_51af = { 02 c0 [2] 26 ce [2] 0d e2 [2] 23 c0 [2] 37 db [2] 38 c1 [2] 26 dc [2] 24 dd [2] 3f db [2] 23 dc [2] 3f f3 }

  condition:
    any of them
}