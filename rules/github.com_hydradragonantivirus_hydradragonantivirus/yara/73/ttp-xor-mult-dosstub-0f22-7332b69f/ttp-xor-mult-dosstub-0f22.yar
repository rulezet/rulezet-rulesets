rule TTP_XOR_MULT_DOSStub_0f22 {
  strings:
    $key_0f22 = { 5b 4a [2] 2f 52 [2] 68 50 [2] 2f 41 [2] 61 4d [2] 6d 47 [2] 7a 4c [2] 61 02 [2] 5c }

  condition:
    any of them
}