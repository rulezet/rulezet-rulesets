rule TTP_XOR_MULT_DOSStub_3fe3 {
  strings:
    $key_3fe3 = { 6b 8b [2] 1f 93 [2] 58 91 [2] 1f 80 [2] 51 8c [2] 5d 86 [2] 4a 8d [2] 51 c3 [2] 6c }

  condition:
    any of them
}