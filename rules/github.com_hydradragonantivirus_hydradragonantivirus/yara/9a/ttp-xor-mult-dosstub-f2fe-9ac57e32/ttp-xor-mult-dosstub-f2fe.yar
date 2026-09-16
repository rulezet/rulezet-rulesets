rule TTP_XOR_MULT_DOSStub_f2fe {
  strings:
    $key_f2fe = { a6 96 [2] d2 8e [2] 95 8c [2] d2 9d [2] 9c 91 [2] 90 9b [2] 87 90 [2] 9c de [2] a1 }

  condition:
    any of them
}