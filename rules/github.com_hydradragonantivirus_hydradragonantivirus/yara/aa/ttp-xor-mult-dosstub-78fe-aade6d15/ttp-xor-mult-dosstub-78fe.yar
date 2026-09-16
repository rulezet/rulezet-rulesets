rule TTP_XOR_MULT_DOSStub_78fe {
  strings:
    $key_78fe = { 2c 96 [2] 58 8e [2] 1f 8c [2] 58 9d [2] 16 91 [2] 1a 9b [2] 0d 90 [2] 16 de [2] 2b }

  condition:
    any of them
}