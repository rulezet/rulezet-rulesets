rule TTP_XOR_MULT_DOSStub_8bb8 {
  strings:
    $key_8bb8 = { df d0 [2] ab c8 [2] ec ca [2] ab db [2] e5 d7 [2] e9 dd [2] fe d6 [2] e5 98 [2] d8 }

  condition:
    any of them
}