rule TTP_XOR_MULT_DOSStub_0f52 {
  strings:
    $key_0f52 = { 5b 3a [2] 2f 22 [2] 68 20 [2] 2f 31 [2] 61 3d [2] 6d 37 [2] 7a 3c [2] 61 72 [2] 5c }

  condition:
    any of them
}