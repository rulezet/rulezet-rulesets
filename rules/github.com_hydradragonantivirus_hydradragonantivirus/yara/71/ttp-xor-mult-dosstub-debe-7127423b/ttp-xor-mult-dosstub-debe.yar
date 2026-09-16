rule TTP_XOR_MULT_DOSStub_debe {
  strings:
    $key_debe = { 8a d6 [2] fe ce [2] b9 cc [2] fe dd [2] b0 d1 [2] bc db [2] ab d0 [2] b0 9e [2] 8d }

  condition:
    any of them
}