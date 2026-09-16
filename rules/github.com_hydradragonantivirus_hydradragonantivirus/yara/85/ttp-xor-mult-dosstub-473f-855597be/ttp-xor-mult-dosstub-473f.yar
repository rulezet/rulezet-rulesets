rule TTP_XOR_MULT_DOSStub_473f {
  strings:
    $key_473f = { 13 57 [2] 67 4f [2] 20 4d [2] 67 5c [2] 29 50 [2] 25 5a [2] 32 51 [2] 29 1f [2] 14 }

  condition:
    any of them
}