rule TTP_XOR_MULT_DOSStub_6c7c {
  strings:
    $key_6c7c = { 38 14 [2] 4c 0c [2] 0b 0e [2] 4c 1f [2] 02 13 [2] 0e 19 [2] 19 12 [2] 02 5c [2] 3f }

  condition:
    any of them
}