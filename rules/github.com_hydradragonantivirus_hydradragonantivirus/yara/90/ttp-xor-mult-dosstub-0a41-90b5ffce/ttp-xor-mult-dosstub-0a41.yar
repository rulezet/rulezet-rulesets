rule TTP_XOR_MULT_DOSStub_0a41 {
  strings:
    $key_0a41 = { 5e 29 [2] 2a 31 [2] 6d 33 [2] 2a 22 [2] 64 2e [2] 68 24 [2] 7f 2f [2] 64 61 [2] 59 }

  condition:
    any of them
}