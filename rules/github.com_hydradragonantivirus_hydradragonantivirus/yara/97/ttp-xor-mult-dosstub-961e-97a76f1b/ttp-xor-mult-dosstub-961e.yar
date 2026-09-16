rule TTP_XOR_MULT_DOSStub_961e {
  strings:
    $key_961e = { c2 76 [2] b6 6e [2] f1 6c [2] b6 7d [2] f8 71 [2] f4 7b [2] e3 70 [2] f8 3e [2] c5 }

  condition:
    any of them
}