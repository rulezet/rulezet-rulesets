rule TTP_XOR_MULT_DOSStub_0d19 {
  strings:
    $key_0d19 = { 59 71 [2] 2d 69 [2] 6a 6b [2] 2d 7a [2] 63 76 [2] 6f 7c [2] 78 77 [2] 63 39 [2] 5e }

  condition:
    any of them
}