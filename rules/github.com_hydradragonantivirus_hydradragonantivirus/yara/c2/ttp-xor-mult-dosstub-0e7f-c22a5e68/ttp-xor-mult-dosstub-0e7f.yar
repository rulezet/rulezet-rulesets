rule TTP_XOR_MULT_DOSStub_0e7f {
  strings:
    $key_0e7f = { 5a 17 [2] 2e 0f [2] 69 0d [2] 2e 1c [2] 60 10 [2] 6c 1a [2] 7b 11 [2] 60 5f [2] 5d }

  condition:
    any of them
}