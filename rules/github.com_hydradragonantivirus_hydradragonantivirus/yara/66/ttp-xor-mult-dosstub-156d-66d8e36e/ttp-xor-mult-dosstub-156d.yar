rule TTP_XOR_MULT_DOSStub_156d {
  strings:
    $key_156d = { 41 05 [2] 35 1d [2] 72 1f [2] 35 0e [2] 7b 02 [2] 77 08 [2] 60 03 [2] 7b 4d [2] 46 }

  condition:
    any of them
}