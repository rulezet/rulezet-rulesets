rule TTP_XOR_MULT_DOSStub_972b {
  strings:
    $key_972b = { c3 43 [2] b7 5b [2] f0 59 [2] b7 48 [2] f9 44 [2] f5 4e [2] e2 45 [2] f9 0b [2] c4 }

  condition:
    any of them
}