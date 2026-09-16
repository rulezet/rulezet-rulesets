rule TTP_XOR_MULT_DOSStub_d88e {
  strings:
    $key_d88e = { 8c e6 [2] f8 fe [2] bf fc [2] f8 ed [2] b6 e1 [2] ba eb [2] ad e0 [2] b6 ae [2] 8b }

  condition:
    any of them
}