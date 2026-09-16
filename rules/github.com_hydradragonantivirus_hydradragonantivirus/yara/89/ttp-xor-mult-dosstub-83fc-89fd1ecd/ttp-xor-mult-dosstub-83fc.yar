rule TTP_XOR_MULT_DOSStub_83fc {
  strings:
    $key_83fc = { d7 94 [2] a3 8c [2] e4 8e [2] a3 9f [2] ed 93 [2] e1 99 [2] f6 92 [2] ed dc [2] d0 }

  condition:
    any of them
}