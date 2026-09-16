rule TTP_XOR_MULT_DOSStub_77fe {
  strings:
    $key_77fe = { 23 96 [2] 57 8e [2] 10 8c [2] 57 9d [2] 19 91 [2] 15 9b [2] 02 90 [2] 19 de [2] 24 }

  condition:
    any of them
}