rule TTP_XOR_MULT_DOSStub_3f02 {
  strings:
    $key_3f02 = { 6b 6a [2] 1f 72 [2] 58 70 [2] 1f 61 [2] 51 6d [2] 5d 67 [2] 4a 6c [2] 51 22 [2] 6c }

  condition:
    any of them
}