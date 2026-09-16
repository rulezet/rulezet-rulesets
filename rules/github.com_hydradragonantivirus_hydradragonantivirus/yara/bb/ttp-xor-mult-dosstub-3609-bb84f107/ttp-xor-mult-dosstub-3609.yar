rule TTP_XOR_MULT_DOSStub_3609 {
  strings:
    $key_3609 = { 62 61 [2] 16 79 [2] 51 7b [2] 16 6a [2] 58 66 [2] 54 6c [2] 43 67 [2] 58 29 [2] 65 }

  condition:
    any of them
}