rule TTP_XOR_MULT_DOSStub_3ff9 {
  strings:
    $key_3ff9 = { 6b 91 [2] 1f 89 [2] 58 8b [2] 1f 9a [2] 51 96 [2] 5d 9c [2] 4a 97 [2] 51 d9 [2] 6c }

  condition:
    any of them
}