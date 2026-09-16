rule TTP_XOR_MULT_DOSStub_605a {
  strings:
    $key_605a = { 34 32 [2] 40 2a [2] 07 28 [2] 40 39 [2] 0e 35 [2] 02 3f [2] 15 34 [2] 0e 7a [2] 33 }

  condition:
    any of them
}