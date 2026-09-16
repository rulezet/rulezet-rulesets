rule TTP_XOR_MULT_DOSStub_1c53 {
  strings:
    $key_1c53 = { 48 3b [2] 3c 23 [2] 7b 21 [2] 3c 30 [2] 72 3c [2] 7e 36 [2] 69 3d [2] 72 73 [2] 4f }

  condition:
    any of them
}