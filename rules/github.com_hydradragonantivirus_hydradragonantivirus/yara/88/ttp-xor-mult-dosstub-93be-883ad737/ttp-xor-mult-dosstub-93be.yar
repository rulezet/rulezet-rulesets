rule TTP_XOR_MULT_DOSStub_93be {
  strings:
    $key_93be = { c7 d6 [2] b3 ce [2] f4 cc [2] b3 dd [2] fd d1 [2] f1 db [2] e6 d0 [2] fd 9e [2] c0 }

  condition:
    any of them
}