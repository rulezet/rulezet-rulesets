rule TTP_XOR_MULT_DOSStub_43fe {
  strings:
    $key_43fe = { 17 96 [2] 63 8e [2] 24 8c [2] 63 9d [2] 2d 91 [2] 21 9b [2] 36 90 [2] 2d de [2] 10 }

  condition:
    any of them
}