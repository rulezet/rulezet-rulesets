rule TTP_XOR_MULT_DOSStub_913a {
  strings:
    $key_913a = { c5 52 [2] b1 4a [2] f6 48 [2] b1 59 [2] ff 55 [2] f3 5f [2] e4 54 [2] ff 1a [2] c2 }

  condition:
    any of them
}