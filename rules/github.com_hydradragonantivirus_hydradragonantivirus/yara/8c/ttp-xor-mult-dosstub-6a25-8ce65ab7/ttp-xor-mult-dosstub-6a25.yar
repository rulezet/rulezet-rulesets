rule TTP_XOR_MULT_DOSStub_6a25 {
  strings:
    $key_6a25 = { 3e 4d [2] 4a 55 [2] 0d 57 [2] 4a 46 [2] 04 4a [2] 08 40 [2] 1f 4b [2] 04 05 [2] 39 }

  condition:
    any of them
}