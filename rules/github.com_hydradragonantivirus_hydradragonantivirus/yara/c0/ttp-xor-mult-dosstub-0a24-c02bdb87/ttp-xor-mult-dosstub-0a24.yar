rule TTP_XOR_MULT_DOSStub_0a24 {
  strings:
    $key_0a24 = { 5e 4c [2] 2a 54 [2] 6d 56 [2] 2a 47 [2] 64 4b [2] 68 41 [2] 7f 4a [2] 64 04 [2] 59 }

  condition:
    any of them
}