rule TTP_XOR_MULT_DOSStub_516f {
  strings:
    $key_516f = { 05 07 [2] 71 1f [2] 36 1d [2] 71 0c [2] 3f 00 [2] 33 0a [2] 24 01 [2] 3f 4f [2] 02 }

  condition:
    any of them
}