rule TTP_XOR_MULT_DOSStub_915f {
  strings:
    $key_915f = { c5 37 [2] b1 2f [2] f6 2d [2] b1 3c [2] ff 30 [2] f3 3a [2] e4 31 [2] ff 7f [2] c2 }

  condition:
    any of them
}