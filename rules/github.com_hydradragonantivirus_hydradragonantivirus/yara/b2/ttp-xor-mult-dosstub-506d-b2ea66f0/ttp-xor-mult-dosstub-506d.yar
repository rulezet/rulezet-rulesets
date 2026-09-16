rule TTP_XOR_MULT_DOSStub_506d {
  strings:
    $key_506d = { 04 05 [2] 70 1d [2] 37 1f [2] 70 0e [2] 3e 02 [2] 32 08 [2] 25 03 [2] 3e 4d [2] 03 }

  condition:
    any of them
}