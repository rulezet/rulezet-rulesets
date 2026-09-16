rule TTP_XOR_MULT_DOSStub_7a7f {
  strings:
    $key_7a7f = { 2e 17 [2] 5a 0f [2] 1d 0d [2] 5a 1c [2] 14 10 [2] 18 1a [2] 0f 11 [2] 14 5f [2] 29 }

  condition:
    any of them
}