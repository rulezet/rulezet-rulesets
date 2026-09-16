rule TTP_XOR_MULT_DOSStub_0a02 {
  strings:
    $key_0a02 = { 5e 6a [2] 2a 72 [2] 6d 70 [2] 2a 61 [2] 64 6d [2] 68 67 [2] 7f 6c [2] 64 22 [2] 59 }

  condition:
    any of them
}