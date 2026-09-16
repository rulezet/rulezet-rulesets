rule TTP_XOR_MULT_DOSStub_6c3c {
  strings:
    $key_6c3c = { 38 54 [2] 4c 4c [2] 0b 4e [2] 4c 5f [2] 02 53 [2] 0e 59 [2] 19 52 [2] 02 1c [2] 3f }

  condition:
    any of them
}