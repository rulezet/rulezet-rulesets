rule TTP_XOR_MULT_DOSStub_6d4c {
  strings:
    $key_6d4c = { 39 24 [2] 4d 3c [2] 0a 3e [2] 4d 2f [2] 03 23 [2] 0f 29 [2] 18 22 [2] 03 6c [2] 3e }

  condition:
    any of them
}