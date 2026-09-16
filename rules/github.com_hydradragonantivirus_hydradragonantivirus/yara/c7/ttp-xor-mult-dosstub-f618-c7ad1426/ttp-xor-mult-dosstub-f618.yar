rule TTP_XOR_MULT_DOSStub_f618 {
  strings:
    $key_f618 = { a2 70 [2] d6 68 [2] 91 6a [2] d6 7b [2] 98 77 [2] 94 7d [2] 83 76 [2] 98 38 [2] a5 }

  condition:
    any of them
}