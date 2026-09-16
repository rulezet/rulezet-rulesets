rule TTP_XOR_MULT_DOSStub_6a19 {
  strings:
    $key_6a19 = { 3e 71 [2] 4a 69 [2] 0d 6b [2] 4a 7a [2] 04 76 [2] 08 7c [2] 1f 77 [2] 04 39 [2] 39 }

  condition:
    any of them
}