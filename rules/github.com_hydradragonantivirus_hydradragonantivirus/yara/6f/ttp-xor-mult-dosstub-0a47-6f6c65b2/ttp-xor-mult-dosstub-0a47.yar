rule TTP_XOR_MULT_DOSStub_0a47 {
  strings:
    $key_0a47 = { 5e 2f [2] 2a 37 [2] 6d 35 [2] 2a 24 [2] 64 28 [2] 68 22 [2] 7f 29 [2] 64 67 [2] 59 }

  condition:
    any of them
}