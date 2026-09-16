rule TTP_XOR_MULT_DOSStub_0a66 {
  strings:
    $key_0a66 = { 5e 0e [2] 2a 16 [2] 6d 14 [2] 2a 05 [2] 64 09 [2] 68 03 [2] 7f 08 [2] 64 46 [2] 59 }

  condition:
    any of them
}