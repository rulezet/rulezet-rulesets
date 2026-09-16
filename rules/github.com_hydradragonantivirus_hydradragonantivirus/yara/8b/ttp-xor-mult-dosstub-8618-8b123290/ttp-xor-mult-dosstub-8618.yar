rule TTP_XOR_MULT_DOSStub_8618 {
  strings:
    $key_8618 = { d2 70 [2] a6 68 [2] e1 6a [2] a6 7b [2] e8 77 [2] e4 7d [2] f3 76 [2] e8 38 [2] d5 }

  condition:
    any of them
}