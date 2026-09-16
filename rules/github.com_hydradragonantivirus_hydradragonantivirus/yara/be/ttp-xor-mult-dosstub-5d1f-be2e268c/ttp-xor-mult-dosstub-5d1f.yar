rule TTP_XOR_MULT_DOSStub_5d1f {
  strings:
    $key_5d1f = { 09 77 [2] 7d 6f [2] 3a 6d [2] 7d 7c [2] 33 70 [2] 3f 7a [2] 28 71 [2] 33 3f [2] 0e }

  condition:
    any of them
}