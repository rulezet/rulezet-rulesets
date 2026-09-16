rule TTP_XOR_MULT_DOSStub_0a05 {
  strings:
    $key_0a05 = { 5e 6d [2] 2a 75 [2] 6d 77 [2] 2a 66 [2] 64 6a [2] 68 60 [2] 7f 6b [2] 64 25 [2] 59 }

  condition:
    any of them
}