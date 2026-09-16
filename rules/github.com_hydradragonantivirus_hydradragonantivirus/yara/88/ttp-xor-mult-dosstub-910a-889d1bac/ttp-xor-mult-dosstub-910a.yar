rule TTP_XOR_MULT_DOSStub_910a {
  strings:
    $key_910a = { c5 62 [2] b1 7a [2] f6 78 [2] b1 69 [2] ff 65 [2] f3 6f [2] e4 64 [2] ff 2a [2] c2 }

  condition:
    any of them
}