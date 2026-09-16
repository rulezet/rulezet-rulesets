rule TTP_XOR_MULT_DOSStub_6016 {
  strings:
    $key_6016 = { 34 7e [2] 40 66 [2] 07 64 [2] 40 75 [2] 0e 79 [2] 02 73 [2] 15 78 [2] 0e 36 [2] 33 }

  condition:
    any of them
}