rule TTP_XOR_MULT_DOSStub_0fe3 {
  strings:
    $key_0fe3 = { 5b 8b [2] 2f 93 [2] 68 91 [2] 2f 80 [2] 61 8c [2] 6d 86 [2] 7a 8d [2] 61 c3 [2] 5c }

  condition:
    any of them
}