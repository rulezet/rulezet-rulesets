rule TTP_XOR_MULT_DOSStub_73fe {
  strings:
    $key_73fe = { 27 96 [2] 53 8e [2] 14 8c [2] 53 9d [2] 1d 91 [2] 11 9b [2] 06 90 [2] 1d de [2] 20 }

  condition:
    any of them
}