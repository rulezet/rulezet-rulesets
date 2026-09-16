rule TTP_XOR_MULT_DOSStub_7f7f {
  strings:
    $key_7f7f = { 2b 17 [2] 5f 0f [2] 18 0d [2] 5f 1c [2] 11 10 [2] 1d 1a [2] 0a 11 [2] 11 5f [2] 2c }

  condition:
    any of them
}