rule TTP_XOR_MULT_DOSStub_230f {
  strings:
    $key_230f = { 77 67 [2] 03 7f [2] 44 7d [2] 03 6c [2] 4d 60 [2] 41 6a [2] 56 61 [2] 4d 2f [2] 70 }

  condition:
    any of them
}