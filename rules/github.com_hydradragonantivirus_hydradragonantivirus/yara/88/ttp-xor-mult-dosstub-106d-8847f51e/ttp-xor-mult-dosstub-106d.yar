rule TTP_XOR_MULT_DOSStub_106d {
  strings:
    $key_106d = { 44 05 [2] 30 1d [2] 77 1f [2] 30 0e [2] 7e 02 [2] 72 08 [2] 65 03 [2] 7e 4d [2] 43 }

  condition:
    any of them
}