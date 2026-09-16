rule TTP_XOR_MULT_DOSStub_976f {
  strings:
    $key_976f = { c3 07 [2] b7 1f [2] f0 1d [2] b7 0c [2] f9 00 [2] f5 0a [2] e2 01 [2] f9 4f [2] c4 }

  condition:
    any of them
}