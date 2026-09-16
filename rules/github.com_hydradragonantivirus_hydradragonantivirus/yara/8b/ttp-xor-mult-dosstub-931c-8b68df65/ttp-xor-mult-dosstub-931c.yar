rule TTP_XOR_MULT_DOSStub_931c {
  strings:
    $key_931c = { c7 74 [2] b3 6c [2] f4 6e [2] b3 7f [2] fd 73 [2] f1 79 [2] e6 72 [2] fd 3c [2] c0 }

  condition:
    any of them
}