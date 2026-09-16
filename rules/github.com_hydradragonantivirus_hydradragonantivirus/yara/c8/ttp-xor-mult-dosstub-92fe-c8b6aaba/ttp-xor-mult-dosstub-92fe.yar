rule TTP_XOR_MULT_DOSStub_92fe {
  strings:
    $key_92fe = { c6 96 [2] b2 8e [2] f5 8c [2] b2 9d [2] fc 91 [2] f0 9b [2] e7 90 [2] fc de [2] c1 }

  condition:
    any of them
}