rule TTP_XOR_MULT_DOSStub_93fc {
  strings:
    $key_93fc = { c7 94 [2] b3 8c [2] f4 8e [2] b3 9f [2] fd 93 [2] f1 99 [2] e6 92 [2] fd dc [2] c0 }

  condition:
    any of them
}