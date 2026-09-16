rule TTP_XOR_MULT_DOSStub_7b7f {
  strings:
    $key_7b7f = { 2f 17 [2] 5b 0f [2] 1c 0d [2] 5b 1c [2] 15 10 [2] 19 1a [2] 0e 11 [2] 15 5f [2] 28 }

  condition:
    any of them
}