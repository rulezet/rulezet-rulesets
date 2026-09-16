rule TTP_XOR_MULT_DOSStub_721f {
  strings:
    $key_721f = { 26 77 [2] 52 6f [2] 15 6d [2] 52 7c [2] 1c 70 [2] 10 7a [2] 07 71 [2] 1c 3f [2] 21 }

  condition:
    any of them
}