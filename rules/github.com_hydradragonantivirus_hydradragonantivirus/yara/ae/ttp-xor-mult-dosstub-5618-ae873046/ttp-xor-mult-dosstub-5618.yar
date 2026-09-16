rule TTP_XOR_MULT_DOSStub_5618 {
  strings:
    $key_5618 = { 02 70 [2] 76 68 [2] 31 6a [2] 76 7b [2] 38 77 [2] 34 7d [2] 23 76 [2] 38 38 [2] 05 }

  condition:
    any of them
}