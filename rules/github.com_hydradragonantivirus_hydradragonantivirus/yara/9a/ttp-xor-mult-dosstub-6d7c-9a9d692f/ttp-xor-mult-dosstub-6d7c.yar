rule TTP_XOR_MULT_DOSStub_6d7c {
  strings:
    $key_6d7c = { 39 14 [2] 4d 0c [2] 0a 0e [2] 4d 1f [2] 03 13 [2] 0f 19 [2] 18 12 [2] 03 5c [2] 3e }

  condition:
    any of them
}