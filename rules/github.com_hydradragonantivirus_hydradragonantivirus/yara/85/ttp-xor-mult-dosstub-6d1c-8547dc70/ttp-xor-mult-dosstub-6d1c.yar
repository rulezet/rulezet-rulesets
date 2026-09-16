rule TTP_XOR_MULT_DOSStub_6d1c {
  strings:
    $key_6d1c = { 39 74 [2] 4d 6c [2] 0a 6e [2] 4d 7f [2] 03 73 [2] 0f 79 [2] 18 72 [2] 03 3c [2] 3e }

  condition:
    any of them
}