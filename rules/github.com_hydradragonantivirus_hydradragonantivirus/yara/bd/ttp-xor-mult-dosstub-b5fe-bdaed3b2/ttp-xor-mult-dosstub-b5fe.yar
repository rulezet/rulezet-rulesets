rule TTP_XOR_MULT_DOSStub_b5fe {
  strings:
    $key_b5fe = { e1 96 [2] 95 8e [2] d2 8c [2] 95 9d [2] db 91 [2] d7 9b [2] c0 90 [2] db de [2] e6 }

  condition:
    any of them
}