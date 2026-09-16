rule TTP_XOR_MULT_DOSStub_076f {
  strings:
    $key_076f = { 53 07 [2] 27 1f [2] 60 1d [2] 27 0c [2] 69 00 [2] 65 0a [2] 72 01 [2] 69 4f [2] 54 }

  condition:
    any of them
}