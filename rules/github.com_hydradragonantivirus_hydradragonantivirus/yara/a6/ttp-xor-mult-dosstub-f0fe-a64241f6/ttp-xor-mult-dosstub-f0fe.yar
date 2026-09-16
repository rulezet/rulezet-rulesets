rule TTP_XOR_MULT_DOSStub_f0fe {
  strings:
    $key_f0fe = { a4 96 [2] d0 8e [2] 97 8c [2] d0 9d [2] 9e 91 [2] 92 9b [2] 85 90 [2] 9e de [2] a3 }

  condition:
    any of them
}