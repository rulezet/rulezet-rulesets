rule TTP_XOR_MULT_DOSStub_565f {
  strings:
    $key_565f = { 02 37 [2] 76 2f [2] 31 2d [2] 76 3c [2] 38 30 [2] 34 3a [2] 23 31 [2] 38 7f [2] 05 }

  condition:
    any of them
}