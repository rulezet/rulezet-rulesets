rule TTP_XOR_MULT_DOSStub_0f43 {
  strings:
    $key_0f43 = { 5b 2b [2] 2f 33 [2] 68 31 [2] 2f 20 [2] 61 2c [2] 6d 26 [2] 7a 2d [2] 61 63 [2] 5c }

  condition:
    any of them
}