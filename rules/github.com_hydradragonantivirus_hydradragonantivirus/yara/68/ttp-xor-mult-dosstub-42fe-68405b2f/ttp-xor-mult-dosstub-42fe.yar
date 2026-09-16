rule TTP_XOR_MULT_DOSStub_42fe {
  strings:
    $key_42fe = { 16 96 [2] 62 8e [2] 25 8c [2] 62 9d [2] 2c 91 [2] 20 9b [2] 37 90 [2] 2c de [2] 11 }

  condition:
    any of them
}