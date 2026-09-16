rule TTP_XOR_MULT_DOSStub_236d {
  strings:
    $key_236d = { 77 05 [2] 03 1d [2] 44 1f [2] 03 0e [2] 4d 02 [2] 41 08 [2] 56 03 [2] 4d 4d [2] 70 }

  condition:
    any of them
}