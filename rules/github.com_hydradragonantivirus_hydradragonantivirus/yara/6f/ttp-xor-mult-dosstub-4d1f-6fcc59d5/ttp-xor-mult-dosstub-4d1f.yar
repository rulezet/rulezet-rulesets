rule TTP_XOR_MULT_DOSStub_4d1f {
  strings:
    $key_4d1f = { 19 77 [2] 6d 6f [2] 2a 6d [2] 6d 7c [2] 23 70 [2] 2f 7a [2] 38 71 [2] 23 3f [2] 1e }

  condition:
    any of them
}