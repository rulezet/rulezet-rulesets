rule TTP_XOR_MULT_DOSStub_0b5a {
  strings:
    $key_0b5a = { 5f 32 [2] 2b 2a [2] 6c 28 [2] 2b 39 [2] 65 35 [2] 69 3f [2] 7e 34 [2] 65 7a [2] 58 }

  condition:
    any of them
}