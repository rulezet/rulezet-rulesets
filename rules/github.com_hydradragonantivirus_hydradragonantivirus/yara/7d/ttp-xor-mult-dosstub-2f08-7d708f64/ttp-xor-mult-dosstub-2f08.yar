rule TTP_XOR_MULT_DOSStub_2f08 {
  strings:
    $key_2f08 = { 7b 60 [2] 0f 78 [2] 48 7a [2] 0f 6b [2] 41 67 [2] 4d 6d [2] 5a 66 [2] 41 28 [2] 7c }

  condition:
    any of them
}