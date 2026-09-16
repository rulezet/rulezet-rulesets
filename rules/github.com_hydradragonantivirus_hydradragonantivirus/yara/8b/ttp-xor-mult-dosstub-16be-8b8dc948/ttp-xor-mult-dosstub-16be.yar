rule TTP_XOR_MULT_DOSStub_16be {
  strings:
    $key_16be = { 42 d6 [2] 36 ce [2] 71 cc [2] 36 dd [2] 78 d1 [2] 74 db [2] 63 d0 [2] 78 9e [2] 45 }

  condition:
    any of them
}