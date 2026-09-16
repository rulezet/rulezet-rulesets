rule TTP_XOR_MULT_DOSStub_2f18 {
  strings:
    $key_2f18 = { 7b 70 [2] 0f 68 [2] 48 6a [2] 0f 7b [2] 41 77 [2] 4d 7d [2] 5a 76 [2] 41 38 [2] 7c }

  condition:
    any of them
}