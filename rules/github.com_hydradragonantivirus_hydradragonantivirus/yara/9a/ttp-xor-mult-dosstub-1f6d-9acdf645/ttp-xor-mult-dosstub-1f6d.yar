rule TTP_XOR_MULT_DOSStub_1f6d {
  strings:
    $key_1f6d = { 4b 05 [2] 3f 1d [2] 78 1f [2] 3f 0e [2] 71 02 [2] 7d 08 [2] 6a 03 [2] 71 4d [2] 4c }

  condition:
    any of them
}