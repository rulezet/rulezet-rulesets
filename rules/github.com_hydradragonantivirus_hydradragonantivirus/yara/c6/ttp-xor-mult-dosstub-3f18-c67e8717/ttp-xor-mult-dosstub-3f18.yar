rule TTP_XOR_MULT_DOSStub_3f18 {
  strings:
    $key_3f18 = { 6b 70 [2] 1f 68 [2] 58 6a [2] 1f 7b [2] 51 77 [2] 5d 7d [2] 4a 76 [2] 51 38 [2] 6c }

  condition:
    any of them
}