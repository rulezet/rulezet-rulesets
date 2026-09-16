rule TTP_XOR_MULT_DOSStub_2618 {
  strings:
    $key_2618 = { 72 70 [2] 06 68 [2] 41 6a [2] 06 7b [2] 48 77 [2] 44 7d [2] 53 76 [2] 48 38 [2] 75 }

  condition:
    any of them
}