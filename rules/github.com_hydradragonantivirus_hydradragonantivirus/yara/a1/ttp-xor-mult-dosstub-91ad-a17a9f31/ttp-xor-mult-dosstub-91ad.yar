rule TTP_XOR_MULT_DOSStub_91ad {
  strings:
    $key_91ad = { c5 c5 [2] b1 dd [2] f6 df [2] b1 ce [2] ff c2 [2] f3 c8 [2] e4 c3 [2] ff 8d [2] c2 }

  condition:
    any of them
}