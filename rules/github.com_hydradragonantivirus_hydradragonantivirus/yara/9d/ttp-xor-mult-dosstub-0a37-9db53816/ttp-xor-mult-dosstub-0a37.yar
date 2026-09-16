rule TTP_XOR_MULT_DOSStub_0a37 {
  strings:
    $key_0a37 = { 5e 5f [2] 2a 47 [2] 6d 45 [2] 2a 54 [2] 64 58 [2] 68 52 [2] 7f 59 [2] 64 17 [2] 59 }

  condition:
    any of them
}