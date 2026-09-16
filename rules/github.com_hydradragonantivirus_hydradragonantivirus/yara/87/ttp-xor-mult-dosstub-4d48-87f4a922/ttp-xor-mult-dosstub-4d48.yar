rule TTP_XOR_MULT_DOSStub_4d48 {
  strings:
    $key_4d48 = { 19 20 [2] 6d 38 [2] 2a 3a [2] 6d 2b [2] 23 27 [2] 2f 2d [2] 38 26 [2] 23 68 [2] 1e }

  condition:
    any of them
}