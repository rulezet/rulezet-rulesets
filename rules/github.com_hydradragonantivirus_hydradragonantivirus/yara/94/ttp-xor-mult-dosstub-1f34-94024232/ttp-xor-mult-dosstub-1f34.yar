rule TTP_XOR_MULT_DOSStub_1f34 {
  strings:
    $key_1f34 = { 4b 5c [2] 3f 44 [2] 78 46 [2] 3f 57 [2] 71 5b [2] 7d 51 [2] 6a 5a [2] 71 14 [2] 4c }

  condition:
    any of them
}