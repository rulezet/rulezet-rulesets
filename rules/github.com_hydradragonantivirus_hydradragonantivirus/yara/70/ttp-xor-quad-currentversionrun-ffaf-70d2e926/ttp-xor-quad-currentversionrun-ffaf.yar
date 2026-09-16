rule TTP_XOR_QUAD_CurrentVersionRun_ffaf {
  strings:
    $key_ffaf = { ac c0 [2] 88 ce [2] a3 e2 [2] 8d c0 [2] 99 db [2] 96 c1 [2] 88 dc [2] 8a dd [2] 91 db [2] 8d dc [2] 91 f3 }

  condition:
    any of them
}