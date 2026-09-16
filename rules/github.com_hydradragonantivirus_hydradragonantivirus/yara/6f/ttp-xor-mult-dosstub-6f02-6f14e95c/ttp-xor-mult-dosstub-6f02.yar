rule TTP_XOR_MULT_DOSStub_6f02 {
  strings:
    $key_6f02 = { 3b 6a [2] 4f 72 [2] 08 70 [2] 4f 61 [2] 01 6d [2] 0d 67 [2] 1a 6c [2] 01 22 [2] 3c }

  condition:
    any of them
}