rule TTP_XOR_MULT_DOSStub_4f1f {
  strings:
    $key_4f1f = { 1b 77 [2] 6f 6f [2] 28 6d [2] 6f 7c [2] 21 70 [2] 2d 7a [2] 3a 71 [2] 21 3f [2] 1c }

  condition:
    any of them
}