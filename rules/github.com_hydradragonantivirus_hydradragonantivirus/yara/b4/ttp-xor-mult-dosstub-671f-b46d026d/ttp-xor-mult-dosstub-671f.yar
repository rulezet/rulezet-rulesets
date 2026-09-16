rule TTP_XOR_MULT_DOSStub_671f {
  strings:
    $key_671f = { 33 77 [2] 47 6f [2] 00 6d [2] 47 7c [2] 09 70 [2] 05 7a [2] 12 71 [2] 09 3f [2] 34 }

  condition:
    any of them
}