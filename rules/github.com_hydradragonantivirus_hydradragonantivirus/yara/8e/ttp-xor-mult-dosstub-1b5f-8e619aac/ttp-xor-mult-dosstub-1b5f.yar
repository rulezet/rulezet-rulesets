rule TTP_XOR_MULT_DOSStub_1b5f {
  strings:
    $key_1b5f = { 4f 37 [2] 3b 2f [2] 7c 2d [2] 3b 3c [2] 75 30 [2] 79 3a [2] 6e 31 [2] 75 7f [2] 48 }

  condition:
    any of them
}