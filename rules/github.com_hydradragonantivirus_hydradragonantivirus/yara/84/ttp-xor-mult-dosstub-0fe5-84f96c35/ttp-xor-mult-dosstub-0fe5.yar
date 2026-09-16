rule TTP_XOR_MULT_DOSStub_0fe5 {
  strings:
    $key_0fe5 = { 5b 8d [2] 2f 95 [2] 68 97 [2] 2f 86 [2] 61 8a [2] 6d 80 [2] 7a 8b [2] 61 c5 [2] 5c }

  condition:
    any of them
}