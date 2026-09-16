rule TTP_XOR_MULT_DOSStub_5ff9 {
  strings:
    $key_5ff9 = { 0b 91 [2] 7f 89 [2] 38 8b [2] 7f 9a [2] 31 96 [2] 3d 9c [2] 2a 97 [2] 31 d9 [2] 0c }

  condition:
    any of them
}