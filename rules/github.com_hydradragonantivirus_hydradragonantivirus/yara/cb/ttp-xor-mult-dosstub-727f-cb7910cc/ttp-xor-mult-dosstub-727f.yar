rule TTP_XOR_MULT_DOSStub_727f {
  strings:
    $key_727f = { 26 17 [2] 52 0f [2] 15 0d [2] 52 1c [2] 1c 10 [2] 10 1a [2] 07 11 [2] 1c 5f [2] 21 }

  condition:
    any of them
}