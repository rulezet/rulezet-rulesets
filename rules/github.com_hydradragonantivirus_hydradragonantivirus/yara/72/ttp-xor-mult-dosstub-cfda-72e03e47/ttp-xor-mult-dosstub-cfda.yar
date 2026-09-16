rule TTP_XOR_MULT_DOSStub_cfda {
  strings:
    $key_cfda = { 9b b2 [2] ef aa [2] a8 a8 [2] ef b9 [2] a1 b5 [2] ad bf [2] ba b4 [2] a1 fa [2] 9c }

  condition:
    any of them
}