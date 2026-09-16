rule TTP_XOR_MULT_DOSStub_17fe {
  strings:
    $key_17fe = { 43 96 [2] 37 8e [2] 70 8c [2] 37 9d [2] 79 91 [2] 75 9b [2] 62 90 [2] 79 de [2] 44 }

  condition:
    any of them
}