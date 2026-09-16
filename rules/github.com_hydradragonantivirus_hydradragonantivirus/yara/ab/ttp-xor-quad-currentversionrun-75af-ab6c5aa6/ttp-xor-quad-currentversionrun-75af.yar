rule TTP_XOR_QUAD_CurrentVersionRun_75af {
  strings:
    $key_75af = { 26 c0 [2] 02 ce [2] 29 e2 [2] 07 c0 [2] 13 db [2] 1c c1 [2] 02 dc [2] 00 dd [2] 1b db [2] 07 dc [2] 1b f3 }

  condition:
    any of them
}