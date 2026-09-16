rule TTP_XOR_MULT_DOSStub_61be {
  strings:
    $key_61be = { 35 d6 [2] 41 ce [2] 06 cc [2] 41 dd [2] 0f d1 [2] 03 db [2] 14 d0 [2] 0f 9e [2] 32 }

  condition:
    any of them
}