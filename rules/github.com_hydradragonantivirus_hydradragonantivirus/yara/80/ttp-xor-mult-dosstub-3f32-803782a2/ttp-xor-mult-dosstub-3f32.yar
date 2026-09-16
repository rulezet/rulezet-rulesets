rule TTP_XOR_MULT_DOSStub_3f32 {
  strings:
    $key_3f32 = { 6b 5a [2] 1f 42 [2] 58 40 [2] 1f 51 [2] 51 5d [2] 5d 57 [2] 4a 5c [2] 51 12 [2] 6c }

  condition:
    any of them
}