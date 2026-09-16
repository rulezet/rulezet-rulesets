rule TTP_XOR_MULT_DOSStub_953f {
  strings:
    $key_953f = { c1 57 [2] b5 4f [2] f2 4d [2] b5 5c [2] fb 50 [2] f7 5a [2] e0 51 [2] fb 1f [2] c6 }

  condition:
    any of them
}