rule TTP_XOR_MULT_DOSStub_2f43 {
  strings:
    $key_2f43 = { 7b 2b [2] 0f 33 [2] 48 31 [2] 0f 20 [2] 41 2c [2] 4d 26 [2] 5a 2d [2] 41 63 [2] 7c }

  condition:
    any of them
}