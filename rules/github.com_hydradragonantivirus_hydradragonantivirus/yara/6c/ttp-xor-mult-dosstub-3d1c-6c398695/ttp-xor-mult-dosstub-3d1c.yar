rule TTP_XOR_MULT_DOSStub_3d1c {
  strings:
    $key_3d1c = { 69 74 [2] 1d 6c [2] 5a 6e [2] 1d 7f [2] 53 73 [2] 5f 79 [2] 48 72 [2] 53 3c [2] 6e }

  condition:
    any of them
}