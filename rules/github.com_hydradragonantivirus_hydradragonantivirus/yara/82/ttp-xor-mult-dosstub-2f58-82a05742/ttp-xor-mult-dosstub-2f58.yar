rule TTP_XOR_MULT_DOSStub_2f58 {
  strings:
    $key_2f58 = { 7b 30 [2] 0f 28 [2] 48 2a [2] 0f 3b [2] 41 37 [2] 4d 3d [2] 5a 36 [2] 41 78 [2] 7c }

  condition:
    any of them
}