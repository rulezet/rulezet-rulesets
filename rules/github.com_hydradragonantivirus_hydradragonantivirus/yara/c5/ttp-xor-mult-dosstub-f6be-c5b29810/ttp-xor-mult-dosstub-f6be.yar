rule TTP_XOR_MULT_DOSStub_f6be {
  strings:
    $key_f6be = { a2 d6 [2] d6 ce [2] 91 cc [2] d6 dd [2] 98 d1 [2] 94 db [2] 83 d0 [2] 98 9e [2] a5 }

  condition:
    any of them
}