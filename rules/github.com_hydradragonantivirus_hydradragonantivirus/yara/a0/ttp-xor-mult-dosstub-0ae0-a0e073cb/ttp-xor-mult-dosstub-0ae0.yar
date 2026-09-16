rule TTP_XOR_MULT_DOSStub_0ae0 {
  strings:
    $key_0ae0 = { 5e 88 [2] 2a 90 [2] 6d 92 [2] 2a 83 [2] 64 8f [2] 68 85 [2] 7f 8e [2] 64 c0 [2] 59 }

  condition:
    any of them
}