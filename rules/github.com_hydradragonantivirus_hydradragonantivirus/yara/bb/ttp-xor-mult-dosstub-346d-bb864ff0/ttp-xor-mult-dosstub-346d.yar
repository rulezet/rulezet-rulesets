rule TTP_XOR_MULT_DOSStub_346d {
  strings:
    $key_346d = { 60 05 [2] 14 1d [2] 53 1f [2] 14 0e [2] 5a 02 [2] 56 08 [2] 41 03 [2] 5a 4d [2] 67 }

  condition:
    any of them
}