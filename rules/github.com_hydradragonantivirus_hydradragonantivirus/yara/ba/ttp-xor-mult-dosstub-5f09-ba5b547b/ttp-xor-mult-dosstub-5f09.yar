rule TTP_XOR_MULT_DOSStub_5f09 {
  strings:
    $key_5f09 = { 0b 61 [2] 7f 79 [2] 38 7b [2] 7f 6a [2] 31 66 [2] 3d 6c [2] 2a 67 [2] 31 29 [2] 0c }

  condition:
    any of them
}