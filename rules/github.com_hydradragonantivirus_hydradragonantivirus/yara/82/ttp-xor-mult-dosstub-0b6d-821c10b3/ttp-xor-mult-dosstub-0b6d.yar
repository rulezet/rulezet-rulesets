rule TTP_XOR_MULT_DOSStub_0b6d {
  strings:
    $key_0b6d = { 5f 05 [2] 2b 1d [2] 6c 1f [2] 2b 0e [2] 65 02 [2] 69 08 [2] 7e 03 [2] 65 4d [2] 58 }

  condition:
    any of them
}