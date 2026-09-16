rule TTP_XOR_MULT_DOSStub_7a1f {
  strings:
    $key_7a1f = { 2e 77 [2] 5a 6f [2] 1d 6d [2] 5a 7c [2] 14 70 [2] 18 7a [2] 0f 71 [2] 14 3f [2] 29 }

  condition:
    any of them
}