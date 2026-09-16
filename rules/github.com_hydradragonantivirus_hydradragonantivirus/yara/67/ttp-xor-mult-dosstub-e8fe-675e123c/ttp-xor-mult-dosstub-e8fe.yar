rule TTP_XOR_MULT_DOSStub_e8fe {
  strings:
    $key_e8fe = { bc 96 [2] c8 8e [2] 8f 8c [2] c8 9d [2] 86 91 [2] 8a 9b [2] 9d 90 [2] 86 de [2] bb }

  condition:
    any of them
}