rule TTP_XOR_MULT_DOSStub_4d6d {
  strings:
    $key_4d6d = { 19 05 [2] 6d 1d [2] 2a 1f [2] 6d 0e [2] 23 02 [2] 2f 08 [2] 38 03 [2] 23 4d [2] 1e }

  condition:
    any of them
}