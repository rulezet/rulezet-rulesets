rule TTP_XOR_MULT_DOSStub_7f32 {
  strings:
    $key_7f32 = { 2b 5a [2] 5f 42 [2] 18 40 [2] 5f 51 [2] 11 5d [2] 1d 57 [2] 0a 5c [2] 11 12 [2] 2c }

  condition:
    any of them
}