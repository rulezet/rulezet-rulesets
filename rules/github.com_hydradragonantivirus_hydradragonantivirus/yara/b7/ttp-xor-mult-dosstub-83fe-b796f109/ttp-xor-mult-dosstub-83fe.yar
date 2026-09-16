rule TTP_XOR_MULT_DOSStub_83fe {
  strings:
    $key_83fe = { d7 96 [2] a3 8e [2] e4 8c [2] a3 9d [2] ed 91 [2] e1 9b [2] f6 90 [2] ed de [2] d0 }

  condition:
    any of them
}