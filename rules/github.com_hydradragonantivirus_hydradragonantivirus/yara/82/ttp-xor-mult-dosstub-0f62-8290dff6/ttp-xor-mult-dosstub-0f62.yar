rule TTP_XOR_MULT_DOSStub_0f62 {
  strings:
    $key_0f62 = { 5b 0a [2] 2f 12 [2] 68 10 [2] 2f 01 [2] 61 0d [2] 6d 07 [2] 7a 0c [2] 61 42 [2] 5c }

  condition:
    any of them
}