rule TTP_XOR_MULT_DOSStub_0b5f {
  strings:
    $key_0b5f = { 5f 37 [2] 2b 2f [2] 6c 2d [2] 2b 3c [2] 65 30 [2] 69 3a [2] 7e 31 [2] 65 7f [2] 58 }

  condition:
    any of them
}