rule TTP_XOR_MULT_DOSStub_1618 {
  strings:
    $key_1618 = { 42 70 [2] 36 68 [2] 71 6a [2] 36 7b [2] 78 77 [2] 74 7d [2] 63 76 [2] 78 38 [2] 45 }

  condition:
    any of them
}