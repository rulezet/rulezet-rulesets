rule TTP_XOR_MULT_DOSStub_2d02 {
  strings:
    $key_2d02 = { 79 6a [2] 0d 72 [2] 4a 70 [2] 0d 61 [2] 43 6d [2] 4f 67 [2] 58 6c [2] 43 22 [2] 7e }

  condition:
    any of them
}