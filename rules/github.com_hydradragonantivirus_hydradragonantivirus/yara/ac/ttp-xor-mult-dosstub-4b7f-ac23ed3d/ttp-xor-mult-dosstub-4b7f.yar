rule TTP_XOR_MULT_DOSStub_4b7f {
  strings:
    $key_4b7f = { 1f 17 [2] 6b 0f [2] 2c 0d [2] 6b 1c [2] 25 10 [2] 29 1a [2] 3e 11 [2] 25 5f [2] 18 }

  condition:
    any of them
}