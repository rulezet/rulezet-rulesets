rule TTP_XOR_MULT_DOSStub_3fe5 {
  strings:
    $key_3fe5 = { 6b 8d [2] 1f 95 [2] 58 97 [2] 1f 86 [2] 51 8a [2] 5d 80 [2] 4a 8b [2] 51 c5 [2] 6c }

  condition:
    any of them
}