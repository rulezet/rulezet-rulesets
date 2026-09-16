rule TTP_XOR_MULT_DOSStub_0e5f {
  strings:
    $key_0e5f = { 5a 37 [2] 2e 2f [2] 69 2d [2] 2e 3c [2] 60 30 [2] 6c 3a [2] 7b 31 [2] 60 7f [2] 5d }

  condition:
    any of them
}