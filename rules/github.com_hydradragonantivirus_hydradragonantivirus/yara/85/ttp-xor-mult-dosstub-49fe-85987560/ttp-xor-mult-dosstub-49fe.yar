rule TTP_XOR_MULT_DOSStub_49fe {
  strings:
    $key_49fe = { 1d 96 [2] 69 8e [2] 2e 8c [2] 69 9d [2] 27 91 [2] 2b 9b [2] 3c 90 [2] 27 de [2] 1a }

  condition:
    any of them
}