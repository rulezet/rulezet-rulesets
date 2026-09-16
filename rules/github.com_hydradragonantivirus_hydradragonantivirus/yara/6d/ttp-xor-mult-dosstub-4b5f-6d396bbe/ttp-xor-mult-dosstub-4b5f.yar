rule TTP_XOR_MULT_DOSStub_4b5f {
  strings:
    $key_4b5f = { 1f 37 [2] 6b 2f [2] 2c 2d [2] 6b 3c [2] 25 30 [2] 29 3a [2] 3e 31 [2] 25 7f [2] 18 }

  condition:
    any of them
}