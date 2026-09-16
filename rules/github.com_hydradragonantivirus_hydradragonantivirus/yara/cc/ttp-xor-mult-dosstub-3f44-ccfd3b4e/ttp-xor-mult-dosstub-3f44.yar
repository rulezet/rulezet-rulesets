rule TTP_XOR_MULT_DOSStub_3f44 {
  strings:
    $key_3f44 = { 6b 2c [2] 1f 34 [2] 58 36 [2] 1f 27 [2] 51 2b [2] 5d 21 [2] 4a 2a [2] 51 64 [2] 6c }

  condition:
    any of them
}