rule TTP_XOR_MULT_DOSStub_5ff8 {
  strings:
    $key_5ff8 = { 0b 90 [2] 7f 88 [2] 38 8a [2] 7f 9b [2] 31 97 [2] 3d 9d [2] 2a 96 [2] 31 d8 [2] 0c }

  condition:
    any of them
}