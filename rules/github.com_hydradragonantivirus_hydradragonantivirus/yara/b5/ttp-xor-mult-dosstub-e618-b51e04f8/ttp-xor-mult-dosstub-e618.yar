rule TTP_XOR_MULT_DOSStub_e618 {
  strings:
    $key_e618 = { b2 70 [2] c6 68 [2] 81 6a [2] c6 7b [2] 88 77 [2] 84 7d [2] 93 76 [2] 88 38 [2] b5 }

  condition:
    any of them
}