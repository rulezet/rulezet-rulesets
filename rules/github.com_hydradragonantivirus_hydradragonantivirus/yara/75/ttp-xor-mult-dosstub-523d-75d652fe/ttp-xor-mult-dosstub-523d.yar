rule TTP_XOR_MULT_DOSStub_523d {
  strings:
    $key_523d = { 06 55 [2] 72 4d [2] 35 4f [2] 72 5e [2] 3c 52 [2] 30 58 [2] 27 53 [2] 3c 1d [2] 01 }

  condition:
    any of them
}