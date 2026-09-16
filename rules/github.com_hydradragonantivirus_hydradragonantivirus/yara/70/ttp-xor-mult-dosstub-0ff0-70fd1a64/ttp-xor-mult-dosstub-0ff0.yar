rule TTP_XOR_MULT_DOSStub_0ff0 {
  strings:
    $key_0ff0 = { 5b 98 [2] 2f 80 [2] 68 82 [2] 2f 93 [2] 61 9f [2] 6d 95 [2] 7a 9e [2] 61 d0 [2] 5c }

  condition:
    any of them
}