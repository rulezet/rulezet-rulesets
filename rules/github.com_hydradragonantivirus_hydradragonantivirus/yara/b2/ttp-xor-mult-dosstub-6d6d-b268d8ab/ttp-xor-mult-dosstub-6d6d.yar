rule TTP_XOR_MULT_DOSStub_6d6d {
  strings:
    $key_6d6d = { 39 05 [2] 4d 1d [2] 0a 1f [2] 4d 0e [2] 03 02 [2] 0f 08 [2] 18 03 [2] 03 4d [2] 3e }

  condition:
    any of them
}