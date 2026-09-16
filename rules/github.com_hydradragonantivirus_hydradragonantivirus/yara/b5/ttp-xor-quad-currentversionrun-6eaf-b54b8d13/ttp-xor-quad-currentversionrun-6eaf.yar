rule TTP_XOR_QUAD_CurrentVersionRun_6eaf {
  strings:
    $key_6eaf = { 3d c0 [2] 19 ce [2] 32 e2 [2] 1c c0 [2] 08 db [2] 07 c1 [2] 19 dc [2] 1b dd [2] 00 db [2] 1c dc [2] 00 f3 }

  condition:
    any of them
}