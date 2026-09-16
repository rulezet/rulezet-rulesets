rule TTP_XOR_MULT_DOSStub_947b {
  strings:
    $key_947b = { c0 13 [2] b4 0b [2] f3 09 [2] b4 18 [2] fa 14 [2] f6 1e [2] e1 15 [2] fa 5b [2] c7 }

  condition:
    any of them
}