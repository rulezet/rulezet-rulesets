rule TTP_XOR_MULT_DOSStub_5f18 {
  strings:
    $key_5f18 = { 0b 70 [2] 7f 68 [2] 38 6a [2] 7f 7b [2] 31 77 [2] 3d 7d [2] 2a 76 [2] 31 38 [2] 0c }

  condition:
    any of them
}