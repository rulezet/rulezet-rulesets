rule TTP_XOR_MULT_DOSStub_91e3 {
  strings:
    $key_91e3 = { c5 8b [2] b1 93 [2] f6 91 [2] b1 80 [2] ff 8c [2] f3 86 [2] e4 8d [2] ff c3 [2] c2 }

  condition:
    any of them
}