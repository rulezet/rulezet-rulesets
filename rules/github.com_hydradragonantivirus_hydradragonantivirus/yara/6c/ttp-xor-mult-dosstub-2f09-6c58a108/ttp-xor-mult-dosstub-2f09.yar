rule TTP_XOR_MULT_DOSStub_2f09 {
  strings:
    $key_2f09 = { 7b 61 [2] 0f 79 [2] 48 7b [2] 0f 6a [2] 41 66 [2] 4d 6c [2] 5a 67 [2] 41 29 [2] 7c }

  condition:
    any of them
}