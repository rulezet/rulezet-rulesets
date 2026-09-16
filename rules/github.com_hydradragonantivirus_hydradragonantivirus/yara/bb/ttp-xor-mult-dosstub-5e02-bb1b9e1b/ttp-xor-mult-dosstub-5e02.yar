rule TTP_XOR_MULT_DOSStub_5e02 {
  strings:
    $key_5e02 = { 0a 6a [2] 7e 72 [2] 39 70 [2] 7e 61 [2] 30 6d [2] 3c 67 [2] 2b 6c [2] 30 22 [2] 0d }

  condition:
    any of them
}