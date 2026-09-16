rule TTP_XOR_MULT_DOSStub_2f48 {
  strings:
    $key_2f48 = { 7b 20 [2] 0f 38 [2] 48 3a [2] 0f 2b [2] 41 27 [2] 4d 2d [2] 5a 26 [2] 41 68 [2] 7c }

  condition:
    any of them
}