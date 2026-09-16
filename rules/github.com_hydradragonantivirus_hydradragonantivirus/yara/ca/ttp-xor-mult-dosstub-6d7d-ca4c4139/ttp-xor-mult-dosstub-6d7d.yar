rule TTP_XOR_MULT_DOSStub_6d7d {
  strings:
    $key_6d7d = { 39 15 [2] 4d 0d [2] 0a 0f [2] 4d 1e [2] 03 12 [2] 0f 18 [2] 18 13 [2] 03 5d [2] 3e }

  condition:
    any of them
}