rule TTP_XOR_MULT_DOSStub_d88c {
  strings:
    $key_d88c = { 8c e4 [2] f8 fc [2] bf fe [2] f8 ef [2] b6 e3 [2] ba e9 [2] ad e2 [2] b6 ac [2] 8b }

  condition:
    any of them
}