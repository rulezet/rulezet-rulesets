rule TTP_XOR_QUAD_CurrentVersionRun_e0af {
  strings:
    $key_e0af = { b3 c0 [2] 97 ce [2] bc e2 [2] 92 c0 [2] 86 db [2] 89 c1 [2] 97 dc [2] 95 dd [2] 8e db [2] 92 dc [2] 8e f3 }

  condition:
    any of them
}