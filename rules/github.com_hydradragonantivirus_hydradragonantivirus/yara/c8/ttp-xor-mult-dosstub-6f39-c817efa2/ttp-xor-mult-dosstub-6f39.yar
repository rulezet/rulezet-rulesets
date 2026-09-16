rule TTP_XOR_MULT_DOSStub_6f39 {
  strings:
    $key_6f39 = { 3b 51 [2] 4f 49 [2] 08 4b [2] 4f 5a [2] 01 56 [2] 0d 5c [2] 1a 57 [2] 01 19 [2] 3c }

  condition:
    any of them
}