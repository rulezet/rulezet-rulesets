rule TTP_XOR_MULT_DOSStub_0e6f {
  strings:
    $key_0e6f = { 5a 07 [2] 2e 1f [2] 69 1d [2] 2e 0c [2] 60 00 [2] 6c 0a [2] 7b 01 [2] 60 4f [2] 5d }

  condition:
    any of them
}