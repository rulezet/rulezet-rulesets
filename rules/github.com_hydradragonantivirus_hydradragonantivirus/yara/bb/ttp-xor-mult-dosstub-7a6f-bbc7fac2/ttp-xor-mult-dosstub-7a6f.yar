rule TTP_XOR_MULT_DOSStub_7a6f {
  strings:
    $key_7a6f = { 2e 07 [2] 5a 1f [2] 1d 1d [2] 5a 0c [2] 14 00 [2] 18 0a [2] 0f 01 [2] 14 4f [2] 29 }

  condition:
    any of them
}