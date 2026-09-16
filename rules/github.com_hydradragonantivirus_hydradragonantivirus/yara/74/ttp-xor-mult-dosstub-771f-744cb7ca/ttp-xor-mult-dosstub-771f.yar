rule TTP_XOR_MULT_DOSStub_771f {
  strings:
    $key_771f = { 23 77 [2] 57 6f [2] 10 6d [2] 57 7c [2] 19 70 [2] 15 7a [2] 02 71 [2] 19 3f [2] 24 }

  condition:
    any of them
}