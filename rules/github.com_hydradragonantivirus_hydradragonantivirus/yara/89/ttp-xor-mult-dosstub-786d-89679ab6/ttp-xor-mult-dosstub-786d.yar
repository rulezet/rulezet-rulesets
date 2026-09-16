rule TTP_XOR_MULT_DOSStub_786d {
  strings:
    $key_786d = { 2c 05 [2] 58 1d [2] 1f 1f [2] 58 0e [2] 16 02 [2] 1a 08 [2] 0d 03 [2] 16 4d [2] 2b }

  condition:
    any of them
}