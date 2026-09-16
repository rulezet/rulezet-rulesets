rule TTP_XOR_MULT_DOSStub_f1fe {
  strings:
    $key_f1fe = { a5 96 [2] d1 8e [2] 96 8c [2] d1 9d [2] 9f 91 [2] 93 9b [2] 84 90 [2] 9f de [2] a2 }

  condition:
    any of them
}