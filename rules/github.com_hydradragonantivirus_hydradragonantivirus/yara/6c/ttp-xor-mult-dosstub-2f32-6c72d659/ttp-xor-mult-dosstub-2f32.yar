rule TTP_XOR_MULT_DOSStub_2f32 {
  strings:
    $key_2f32 = { 7b 5a [2] 0f 42 [2] 48 40 [2] 0f 51 [2] 41 5d [2] 4d 57 [2] 5a 5c [2] 41 12 [2] 7c }

  condition:
    any of them
}