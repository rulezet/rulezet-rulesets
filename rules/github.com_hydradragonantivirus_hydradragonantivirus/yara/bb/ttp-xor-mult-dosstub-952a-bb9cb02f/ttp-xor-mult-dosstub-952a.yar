rule TTP_XOR_MULT_DOSStub_952a {
  strings:
    $key_952a = { c1 42 [2] b5 5a [2] f2 58 [2] b5 49 [2] fb 45 [2] f7 4f [2] e0 44 [2] fb 0a [2] c6 }

  condition:
    any of them
}