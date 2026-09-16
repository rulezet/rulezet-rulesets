rule TTP_XOR_MULT_DOSStub_003f {
  strings:
    $key_003f = { 54 57 [2] 20 4f [2] 67 4d [2] 20 5c [2] 6e 50 [2] 62 5a [2] 75 51 [2] 6e 1f [2] 53 }

  condition:
    any of them
}