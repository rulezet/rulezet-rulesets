rule TTP_XOR_MULT_DOSStub_3f6d {
  strings:
    $key_3f6d = { 6b 05 [2] 1f 1d [2] 58 1f [2] 1f 0e [2] 51 02 [2] 5d 08 [2] 4a 03 [2] 51 4d [2] 6c }

  condition:
    any of them
}