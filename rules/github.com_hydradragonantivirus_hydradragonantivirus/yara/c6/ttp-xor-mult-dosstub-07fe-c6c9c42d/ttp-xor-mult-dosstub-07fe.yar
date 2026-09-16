rule TTP_XOR_MULT_DOSStub_07fe {
  strings:
    $key_07fe = { 53 96 [2] 27 8e [2] 60 8c [2] 27 9d [2] 69 91 [2] 65 9b [2] 72 90 [2] 69 de [2] 54 }

  condition:
    any of them
}