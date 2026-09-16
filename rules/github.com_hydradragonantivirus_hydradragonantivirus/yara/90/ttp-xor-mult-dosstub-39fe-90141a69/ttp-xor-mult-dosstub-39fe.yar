rule TTP_XOR_MULT_DOSStub_39fe {
  strings:
    $key_39fe = { 6d 96 [2] 19 8e [2] 5e 8c [2] 19 9d [2] 57 91 [2] 5b 9b [2] 4c 90 [2] 57 de [2] 6a }

  condition:
    any of them
}