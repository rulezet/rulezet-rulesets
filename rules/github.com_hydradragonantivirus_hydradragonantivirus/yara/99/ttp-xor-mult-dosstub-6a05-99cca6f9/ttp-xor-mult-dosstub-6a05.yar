rule TTP_XOR_MULT_DOSStub_6a05 {
  strings:
    $key_6a05 = { 3e 6d [2] 4a 75 [2] 0d 77 [2] 4a 66 [2] 04 6a [2] 08 60 [2] 1f 6b [2] 04 25 [2] 39 }

  condition:
    any of them
}