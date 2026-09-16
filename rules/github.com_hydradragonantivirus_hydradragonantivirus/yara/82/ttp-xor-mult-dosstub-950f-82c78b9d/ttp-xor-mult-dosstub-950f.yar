rule TTP_XOR_MULT_DOSStub_950f {
  strings:
    $key_950f = { c1 67 [2] b5 7f [2] f2 7d [2] b5 6c [2] fb 60 [2] f7 6a [2] e0 61 [2] fb 2f [2] c6 }

  condition:
    any of them
}