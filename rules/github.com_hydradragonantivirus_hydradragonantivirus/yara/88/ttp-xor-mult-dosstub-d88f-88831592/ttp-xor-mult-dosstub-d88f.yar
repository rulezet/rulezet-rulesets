rule TTP_XOR_MULT_DOSStub_d88f {
  strings:
    $key_d88f = { 8c e7 [2] f8 ff [2] bf fd [2] f8 ec [2] b6 e0 [2] ba ea [2] ad e1 [2] b6 af [2] 8b }

  condition:
    any of them
}