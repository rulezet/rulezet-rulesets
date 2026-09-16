rule TTP_XOR_MULT_DOSStub_516d {
  strings:
    $key_516d = { 05 05 [2] 71 1d [2] 36 1f [2] 71 0e [2] 3f 02 [2] 33 08 [2] 24 03 [2] 3f 4d [2] 02 }

  condition:
    any of them
}