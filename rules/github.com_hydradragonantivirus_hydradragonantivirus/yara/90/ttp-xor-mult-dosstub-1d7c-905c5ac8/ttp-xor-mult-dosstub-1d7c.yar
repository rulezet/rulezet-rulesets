rule TTP_XOR_MULT_DOSStub_1d7c {
  strings:
    $key_1d7c = { 49 14 [2] 3d 0c [2] 7a 0e [2] 3d 1f [2] 73 13 [2] 7f 19 [2] 68 12 [2] 73 5c [2] 4e }

  condition:
    any of them
}