rule TTP_XOR_MULT_DOSStub_6f08 {
  strings:
    $key_6f08 = { 3b 60 [2] 4f 78 [2] 08 7a [2] 4f 6b [2] 01 67 [2] 0d 6d [2] 1a 66 [2] 01 28 [2] 3c }

  condition:
    any of them
}