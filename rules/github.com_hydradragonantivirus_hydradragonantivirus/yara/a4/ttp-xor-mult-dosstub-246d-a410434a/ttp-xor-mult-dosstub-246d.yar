rule TTP_XOR_MULT_DOSStub_246d {
  strings:
    $key_246d = { 70 05 [2] 04 1d [2] 43 1f [2] 04 0e [2] 4a 02 [2] 46 08 [2] 51 03 [2] 4a 4d [2] 77 }

  condition:
    any of them
}