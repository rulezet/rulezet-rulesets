rule TTP_XOR_MULT_DOSStub_0f45 {
  strings:
    $key_0f45 = { 5b 2d [2] 2f 35 [2] 68 37 [2] 2f 26 [2] 61 2a [2] 6d 20 [2] 7a 2b [2] 61 65 [2] 5c }

  condition:
    any of them
}