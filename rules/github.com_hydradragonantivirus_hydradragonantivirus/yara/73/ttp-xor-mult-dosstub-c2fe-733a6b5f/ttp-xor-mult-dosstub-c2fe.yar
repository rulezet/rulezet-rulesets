rule TTP_XOR_MULT_DOSStub_c2fe {
  strings:
    $key_c2fe = { 96 96 [2] e2 8e [2] a5 8c [2] e2 9d [2] ac 91 [2] a0 9b [2] b7 90 [2] ac de [2] 91 }

  condition:
    any of them
}