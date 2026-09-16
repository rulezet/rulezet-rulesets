rule TTP_XOR_MULT_DOSStub_912d {
  strings:
    $key_912d = { c5 45 [2] b1 5d [2] f6 5f [2] b1 4e [2] ff 42 [2] f3 48 [2] e4 43 [2] ff 0d [2] c2 }

  condition:
    any of them
}