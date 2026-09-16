rule TTP_XOR_MULT_DOSStub_196d {
  strings:
    $key_196d = { 4d 05 [2] 39 1d [2] 7e 1f [2] 39 0e [2] 77 02 [2] 7b 08 [2] 6c 03 [2] 77 4d [2] 4a }

  condition:
    any of them
}