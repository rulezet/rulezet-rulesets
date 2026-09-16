rule TTP_XOR_MULT_DOSStub_4a3c {
  strings:
    $key_4a3c = { 1e 54 [2] 6a 4c [2] 2d 4e [2] 6a 5f [2] 24 53 [2] 28 59 [2] 3f 52 [2] 24 1c [2] 19 }

  condition:
    any of them
}