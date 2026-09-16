rule TTP_XOR_MULT_DOSStub_631f {
  strings:
    $key_631f = { 37 77 [2] 43 6f [2] 04 6d [2] 43 7c [2] 0d 70 [2] 01 7a [2] 16 71 [2] 0d 3f [2] 30 }

  condition:
    any of them
}