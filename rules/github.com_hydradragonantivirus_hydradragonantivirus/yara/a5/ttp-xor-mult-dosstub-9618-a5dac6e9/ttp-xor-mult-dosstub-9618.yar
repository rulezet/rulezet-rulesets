rule TTP_XOR_MULT_DOSStub_9618 {
  strings:
    $key_9618 = { c2 70 [2] b6 68 [2] f1 6a [2] b6 7b [2] f8 77 [2] f4 7d [2] e3 76 [2] f8 38 [2] c5 }

  condition:
    any of them
}