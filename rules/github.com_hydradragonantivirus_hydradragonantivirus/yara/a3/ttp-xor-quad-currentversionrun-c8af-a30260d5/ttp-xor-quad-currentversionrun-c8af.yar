rule TTP_XOR_QUAD_CurrentVersionRun_c8af {
  strings:
    $key_c8af = { 9b c0 [2] bf ce [2] 94 e2 [2] ba c0 [2] ae db [2] a1 c1 [2] bf dc [2] bd dd [2] a6 db [2] ba dc [2] a6 f3 }

  condition:
    any of them
}