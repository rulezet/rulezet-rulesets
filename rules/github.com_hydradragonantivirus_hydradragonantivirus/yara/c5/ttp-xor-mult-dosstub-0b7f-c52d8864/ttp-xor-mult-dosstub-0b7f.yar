rule TTP_XOR_MULT_DOSStub_0b7f {
  strings:
    $key_0b7f = { 5f 17 [2] 2b 0f [2] 6c 0d [2] 2b 1c [2] 65 10 [2] 69 1a [2] 7e 11 [2] 65 5f [2] 58 }

  condition:
    any of them
}