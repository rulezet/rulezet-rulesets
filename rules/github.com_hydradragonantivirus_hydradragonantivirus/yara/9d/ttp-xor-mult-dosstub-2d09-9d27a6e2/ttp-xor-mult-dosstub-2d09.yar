rule TTP_XOR_MULT_DOSStub_2d09 {
  strings:
    $key_2d09 = { 79 61 [2] 0d 79 [2] 4a 7b [2] 0d 6a [2] 43 66 [2] 4f 6c [2] 58 67 [2] 43 29 [2] 7e }

  condition:
    any of them
}