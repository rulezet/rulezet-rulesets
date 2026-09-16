rule TTP_XOR_MULT_DOSStub_971e {
  strings:
    $key_971e = { c3 76 [2] b7 6e [2] f0 6c [2] b7 7d [2] f9 71 [2] f5 7b [2] e2 70 [2] f9 3e [2] c4 }

  condition:
    any of them
}