rule TTP_XOR_MULT_DOSStub_5f39 {
  strings:
    $key_5f39 = { 0b 51 [2] 7f 49 [2] 38 4b [2] 7f 5a [2] 31 56 [2] 3d 5c [2] 2a 57 [2] 31 19 [2] 0c }

  condition:
    any of them
}