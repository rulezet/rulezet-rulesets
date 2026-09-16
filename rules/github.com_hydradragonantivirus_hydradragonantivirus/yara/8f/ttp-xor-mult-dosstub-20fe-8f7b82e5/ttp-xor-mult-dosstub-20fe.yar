rule TTP_XOR_MULT_DOSStub_20fe {
  strings:
    $key_20fe = { 74 96 [2] 00 8e [2] 47 8c [2] 00 9d [2] 4e 91 [2] 42 9b [2] 55 90 [2] 4e de [2] 73 }

  condition:
    any of them
}