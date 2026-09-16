rule TTP_XOR_MULT_DOSStub_453f {
  strings:
    $key_453f = { 11 57 [2] 65 4f [2] 22 4d [2] 65 5c [2] 2b 50 [2] 27 5a [2] 30 51 [2] 2b 1f [2] 16 }

  condition:
    any of them
}