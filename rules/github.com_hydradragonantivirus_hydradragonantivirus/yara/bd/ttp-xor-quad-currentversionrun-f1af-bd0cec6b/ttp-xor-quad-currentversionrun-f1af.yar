rule TTP_XOR_QUAD_CurrentVersionRun_f1af {
  strings:
    $key_f1af = { a2 c0 [2] 86 ce [2] ad e2 [2] 83 c0 [2] 97 db [2] 98 c1 [2] 86 dc [2] 84 dd [2] 9f db [2] 83 dc [2] 9f f3 }

  condition:
    any of them
}