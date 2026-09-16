rule TTP_XOR_MULT_DOSStub_571f {
  strings:
    $key_571f = { 03 77 [2] 77 6f [2] 30 6d [2] 77 7c [2] 39 70 [2] 35 7a [2] 22 71 [2] 39 3f [2] 04 }

  condition:
    any of them
}