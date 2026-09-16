rule TTP_XOR_MULT_DOSStub_1f32 {
  strings:
    $key_1f32 = { 4b 5a [2] 3f 42 [2] 78 40 [2] 3f 51 [2] 71 5d [2] 7d 57 [2] 6a 5c [2] 71 12 [2] 4c }

  condition:
    any of them
}