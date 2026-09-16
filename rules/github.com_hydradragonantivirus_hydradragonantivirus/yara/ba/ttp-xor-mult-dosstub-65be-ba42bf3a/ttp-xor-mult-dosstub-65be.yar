rule TTP_XOR_MULT_DOSStub_65be {
  strings:
    $key_65be = { 31 d6 [2] 45 ce [2] 02 cc [2] 45 dd [2] 0b d1 [2] 07 db [2] 10 d0 [2] 0b 9e [2] 36 }

  condition:
    any of them
}