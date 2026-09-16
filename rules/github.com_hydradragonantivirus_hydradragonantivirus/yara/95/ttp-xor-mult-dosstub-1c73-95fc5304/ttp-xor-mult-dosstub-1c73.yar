rule TTP_XOR_MULT_DOSStub_1c73 {
  strings:
    $key_1c73 = { 48 1b [2] 3c 03 [2] 7b 01 [2] 3c 10 [2] 72 1c [2] 7e 16 [2] 69 1d [2] 72 53 [2] 4f }

  condition:
    any of them
}