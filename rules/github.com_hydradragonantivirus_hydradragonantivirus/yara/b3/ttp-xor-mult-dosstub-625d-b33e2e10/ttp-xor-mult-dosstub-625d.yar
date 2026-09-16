rule TTP_XOR_MULT_DOSStub_625d {
  strings:
    $key_625d = { 36 35 [2] 42 2d [2] 05 2f [2] 42 3e [2] 0c 32 [2] 00 38 [2] 17 33 [2] 0c 7d [2] 31 }

  condition:
    any of them
}