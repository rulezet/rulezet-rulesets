rule TTP_XOR_MULT_DOSStub_942a {
  strings:
    $key_942a = { c0 42 [2] b4 5a [2] f3 58 [2] b4 49 [2] fa 45 [2] f6 4f [2] e1 44 [2] fa 0a [2] c7 }

  condition:
    any of them
}