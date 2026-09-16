rule TTP_XOR_MULT_DOSStub_446f {
  strings:
    $key_446f = { 10 07 [2] 64 1f [2] 23 1d [2] 64 0c [2] 2a 00 [2] 26 0a [2] 31 01 [2] 2a 4f [2] 17 }

  condition:
    any of them
}