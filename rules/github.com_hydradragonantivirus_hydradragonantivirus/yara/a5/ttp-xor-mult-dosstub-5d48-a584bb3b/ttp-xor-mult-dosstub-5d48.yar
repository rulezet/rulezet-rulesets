rule TTP_XOR_MULT_DOSStub_5d48 {
  strings:
    $key_5d48 = { 09 20 [2] 7d 38 [2] 3a 3a [2] 7d 2b [2] 33 27 [2] 3f 2d [2] 28 26 [2] 33 68 [2] 0e }

  condition:
    any of them
}