rule TTP_XOR_MULT_DOSStub_5ff4 {
  strings:
    $key_5ff4 = { 0b 9c [2] 7f 84 [2] 38 86 [2] 7f 97 [2] 31 9b [2] 3d 91 [2] 2a 9a [2] 31 d4 [2] 0c }

  condition:
    any of them
}