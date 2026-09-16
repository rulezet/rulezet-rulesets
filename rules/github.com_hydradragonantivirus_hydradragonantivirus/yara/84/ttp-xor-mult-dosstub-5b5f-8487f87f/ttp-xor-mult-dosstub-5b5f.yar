rule TTP_XOR_MULT_DOSStub_5b5f {
  strings:
    $key_5b5f = { 0f 37 [2] 7b 2f [2] 3c 2d [2] 7b 3c [2] 35 30 [2] 39 3a [2] 2e 31 [2] 35 7f [2] 08 }

  condition:
    any of them
}