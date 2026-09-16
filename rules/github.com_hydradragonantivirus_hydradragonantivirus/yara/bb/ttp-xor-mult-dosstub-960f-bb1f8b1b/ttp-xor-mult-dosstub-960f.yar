rule TTP_XOR_MULT_DOSStub_960f {
  strings:
    $key_960f = { c2 67 [2] b6 7f [2] f1 7d [2] b6 6c [2] f8 60 [2] f4 6a [2] e3 61 [2] f8 2f [2] c5 }

  condition:
    any of them
}