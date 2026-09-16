rule TTP_XOR_MULT_DOSStub_913f {
  strings:
    $key_913f = { c5 57 [2] b1 4f [2] f6 4d [2] b1 5c [2] ff 50 [2] f3 5a [2] e4 51 [2] ff 1f [2] c2 }

  condition:
    any of them
}