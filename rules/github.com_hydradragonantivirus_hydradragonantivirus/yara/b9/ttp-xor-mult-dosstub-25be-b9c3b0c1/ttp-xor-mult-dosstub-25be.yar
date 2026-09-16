rule TTP_XOR_MULT_DOSStub_25be {
  strings:
    $key_25be = { 71 d6 [2] 05 ce [2] 42 cc [2] 05 dd [2] 4b d1 [2] 47 db [2] 50 d0 [2] 4b 9e [2] 76 }

  condition:
    any of them
}