rule TTP_XOR_MULT_DOSStub_5a3c {
  strings:
    $key_5a3c = { 0e 54 [2] 7a 4c [2] 3d 4e [2] 7a 5f [2] 34 53 [2] 38 59 [2] 2f 52 [2] 34 1c [2] 09 }

  condition:
    any of them
}