rule TTP_XOR_MULT_DOSStub_5a4c {
  strings:
    $key_5a4c = { 0e 24 [2] 7a 3c [2] 3d 3e [2] 7a 2f [2] 34 23 [2] 38 29 [2] 2f 22 [2] 34 6c [2] 09 }

  condition:
    any of them
}