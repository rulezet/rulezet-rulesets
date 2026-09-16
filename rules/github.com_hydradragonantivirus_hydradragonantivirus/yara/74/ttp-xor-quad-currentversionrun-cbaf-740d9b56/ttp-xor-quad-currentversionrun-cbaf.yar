rule TTP_XOR_QUAD_CurrentVersionRun_cbaf {
  strings:
    $key_cbaf = { 98 c0 [2] bc ce [2] 97 e2 [2] b9 c0 [2] ad db [2] a2 c1 [2] bc dc [2] be dd [2] a5 db [2] b9 dc [2] a5 f3 }

  condition:
    any of them
}