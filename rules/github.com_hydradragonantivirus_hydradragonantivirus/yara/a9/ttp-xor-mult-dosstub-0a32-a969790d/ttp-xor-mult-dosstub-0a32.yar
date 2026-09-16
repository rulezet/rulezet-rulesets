rule TTP_XOR_MULT_DOSStub_0a32 {
  strings:
    $key_0a32 = { 5e 5a [2] 2a 42 [2] 6d 40 [2] 2a 51 [2] 64 5d [2] 68 57 [2] 7f 5c [2] 64 12 [2] 59 }

  condition:
    any of them
}