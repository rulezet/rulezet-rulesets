rule TTP_XOR_MULT_DOSStub_dead {
  strings:
    $key_dead = { 8a c5 [2] fe dd [2] b9 df [2] fe ce [2] b0 c2 [2] bc c8 [2] ab c3 [2] b0 8d [2] 8d }

  condition:
    any of them
}