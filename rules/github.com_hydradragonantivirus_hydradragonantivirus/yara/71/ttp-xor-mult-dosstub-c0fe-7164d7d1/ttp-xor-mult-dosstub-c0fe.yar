rule TTP_XOR_MULT_DOSStub_c0fe {
  strings:
    $key_c0fe = { 94 96 [2] e0 8e [2] a7 8c [2] e0 9d [2] ae 91 [2] a2 9b [2] b5 90 [2] ae de [2] 93 }

  condition:
    any of them
}