rule TTP_XOR_MULT_DOSStub_0f58 {
  strings:
    $key_0f58 = { 5b 30 [2] 2f 28 [2] 68 2a [2] 2f 3b [2] 61 37 [2] 6d 3d [2] 7a 36 [2] 61 78 [2] 5c }

  condition:
    any of them
}