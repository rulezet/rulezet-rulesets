rule TTP_XOR_MULT_DOSStub_6a18 {
  strings:
    $key_6a18 = { 3e 70 [2] 4a 68 [2] 0d 6a [2] 4a 7b [2] 04 77 [2] 08 7d [2] 1f 76 [2] 04 38 [2] 39 }

  condition:
    any of them
}