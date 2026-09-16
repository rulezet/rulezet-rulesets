rule TTP_XOR_QUAD_CurrentVersionRun_16af {
  strings:
    $key_16af = { 45 c0 [2] 61 ce [2] 4a e2 [2] 64 c0 [2] 70 db [2] 7f c1 [2] 61 dc [2] 63 dd [2] 78 db [2] 64 dc [2] 78 f3 }

  condition:
    any of them
}