rule TTP_XOR_MULT_DOSStub_952d {
  strings:
    $key_952d = { c1 45 [2] b5 5d [2] f2 5f [2] b5 4e [2] fb 42 [2] f7 48 [2] e0 43 [2] fb 0d [2] c6 }

  condition:
    any of them
}