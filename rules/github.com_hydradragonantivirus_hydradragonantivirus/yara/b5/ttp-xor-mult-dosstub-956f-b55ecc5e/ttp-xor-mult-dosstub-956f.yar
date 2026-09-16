rule TTP_XOR_MULT_DOSStub_956f {
  strings:
    $key_956f = { c1 07 [2] b5 1f [2] f2 1d [2] b5 0c [2] fb 00 [2] f7 0a [2] e0 01 [2] fb 4f [2] c6 }

  condition:
    any of them
}