rule TTP_XOR_MULT_DOSStub_912b {
  strings:
    $key_912b = { c5 43 [2] b1 5b [2] f6 59 [2] b1 48 [2] ff 44 [2] f3 4e [2] e4 45 [2] ff 0b [2] c2 }

  condition:
    any of them
}