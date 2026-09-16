rule TTP_XOR_MULT_DOSStub_5f62 {
  strings:
    $key_5f62 = { 0b 0a [2] 7f 12 [2] 38 10 [2] 7f 01 [2] 31 0d [2] 3d 07 [2] 2a 0c [2] 31 42 [2] 0c }

  condition:
    any of them
}