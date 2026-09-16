rule TTP_XOR_MULT_DOSStub_3f08 {
  strings:
    $key_3f08 = { 6b 60 [2] 1f 78 [2] 58 7a [2] 1f 6b [2] 51 67 [2] 5d 6d [2] 4a 66 [2] 51 28 [2] 6c }

  condition:
    any of them
}