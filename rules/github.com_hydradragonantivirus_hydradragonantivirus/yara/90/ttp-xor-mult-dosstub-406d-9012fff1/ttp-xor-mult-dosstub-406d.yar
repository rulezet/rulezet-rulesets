rule TTP_XOR_MULT_DOSStub_406d {
  strings:
    $key_406d = { 14 05 [2] 60 1d [2] 27 1f [2] 60 0e [2] 2e 02 [2] 22 08 [2] 35 03 [2] 2e 4d [2] 13 }

  condition:
    any of them
}