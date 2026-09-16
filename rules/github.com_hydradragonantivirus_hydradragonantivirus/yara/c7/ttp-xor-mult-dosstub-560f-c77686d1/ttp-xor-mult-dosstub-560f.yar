rule TTP_XOR_MULT_DOSStub_560f {
  strings:
    $key_560f = { 02 67 [2] 76 7f [2] 31 7d [2] 76 6c [2] 38 60 [2] 34 6a [2] 23 61 [2] 38 2f [2] 05 }

  condition:
    any of them
}