rule TTP_XOR_MULT_DOSStub_66fe {
  strings:
    $key_66fe = { 32 96 [2] 46 8e [2] 01 8c [2] 46 9d [2] 08 91 [2] 04 9b [2] 13 90 [2] 08 de [2] 35 }

  condition:
    any of them
}