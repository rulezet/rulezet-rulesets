rule TTP_XOR_MULT_DOSStub_1d1c {
  strings:
    $key_1d1c = { 49 74 [2] 3d 6c [2] 7a 6e [2] 3d 7f [2] 73 73 [2] 7f 79 [2] 68 72 [2] 73 3c [2] 4e }

  condition:
    any of them
}