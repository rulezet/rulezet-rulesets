rule TTP_XOR_MULT_DOSStub_67fe {
  strings:
    $key_67fe = { 33 96 [2] 47 8e [2] 00 8c [2] 47 9d [2] 09 91 [2] 05 9b [2] 12 90 [2] 09 de [2] 34 }

  condition:
    any of them
}