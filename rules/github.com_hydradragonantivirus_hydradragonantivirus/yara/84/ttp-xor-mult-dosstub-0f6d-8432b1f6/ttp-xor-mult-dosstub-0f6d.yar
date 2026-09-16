rule TTP_XOR_MULT_DOSStub_0f6d {
  strings:
    $key_0f6d = { 5b 05 [2] 2f 1d [2] 68 1f [2] 2f 0e [2] 61 02 [2] 6d 08 [2] 7a 03 [2] 61 4d [2] 5c }

  condition:
    any of them
}