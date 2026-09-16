rule TTP_XOR_MULT_DOSStub_0a08 {
  strings:
    $key_0a08 = { 5e 60 [2] 2a 78 [2] 6d 7a [2] 2a 6b [2] 64 67 [2] 68 6d [2] 7f 66 [2] 64 28 [2] 59 }

  condition:
    any of them
}