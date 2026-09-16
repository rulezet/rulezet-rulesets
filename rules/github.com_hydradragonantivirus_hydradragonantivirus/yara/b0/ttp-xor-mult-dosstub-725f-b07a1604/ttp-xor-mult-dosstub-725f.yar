rule TTP_XOR_MULT_DOSStub_725f {
  strings:
    $key_725f = { 26 37 [2] 52 2f [2] 15 2d [2] 52 3c [2] 1c 30 [2] 10 3a [2] 07 31 [2] 1c 7f [2] 21 }

  condition:
    any of them
}