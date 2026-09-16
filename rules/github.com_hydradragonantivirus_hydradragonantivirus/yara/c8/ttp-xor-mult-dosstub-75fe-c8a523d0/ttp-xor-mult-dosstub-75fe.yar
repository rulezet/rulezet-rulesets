rule TTP_XOR_MULT_DOSStub_75fe {
  strings:
    $key_75fe = { 21 96 [2] 55 8e [2] 12 8c [2] 55 9d [2] 1b 91 [2] 17 9b [2] 00 90 [2] 1b de [2] 26 }

  condition:
    any of them
}