rule TTP_XOR_MULT_DOSStub_962b {
  strings:
    $key_962b = { c2 43 [2] b6 5b [2] f1 59 [2] b6 48 [2] f8 44 [2] f4 4e [2] e3 45 [2] f8 0b [2] c5 }

  condition:
    any of them
}