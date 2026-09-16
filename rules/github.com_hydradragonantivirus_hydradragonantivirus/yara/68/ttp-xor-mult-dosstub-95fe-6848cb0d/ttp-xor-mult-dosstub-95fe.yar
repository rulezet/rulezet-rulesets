rule TTP_XOR_MULT_DOSStub_95fe {
  strings:
    $key_95fe = { c1 96 [2] b5 8e [2] f2 8c [2] b5 9d [2] fb 91 [2] f7 9b [2] e0 90 [2] fb de [2] c6 }

  condition:
    any of them
}