rule TTP_XOR_MULT_DOSStub_6d4e {
  strings:
    $key_6d4e = { 39 26 [2] 4d 3e [2] 0a 3c [2] 4d 2d [2] 03 21 [2] 0f 2b [2] 18 20 [2] 03 6e [2] 3e }

  condition:
    any of them
}