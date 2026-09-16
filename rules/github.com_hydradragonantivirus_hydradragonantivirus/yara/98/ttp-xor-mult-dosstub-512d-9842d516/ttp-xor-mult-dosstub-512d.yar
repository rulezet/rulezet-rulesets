rule TTP_XOR_MULT_DOSStub_512d {
  strings:
    $key_512d = { 05 45 [2] 71 5d [2] 36 5f [2] 71 4e [2] 3f 42 [2] 33 48 [2] 24 43 [2] 3f 0d [2] 02 }

  condition:
    any of them
}