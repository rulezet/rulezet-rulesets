rule TTP_XOR_QUAD_CurrentVersionRun_4faf {
  strings:
    $key_4faf = { 1c c0 [2] 38 ce [2] 13 e2 [2] 3d c0 [2] 29 db [2] 26 c1 [2] 38 dc [2] 3a dd [2] 21 db [2] 3d dc [2] 21 f3 }

  condition:
    any of them
}