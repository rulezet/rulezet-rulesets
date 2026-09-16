rule TTP_XOR_MULT_DOSStub_0ae7 {
  strings:
    $key_0ae7 = { 5e 8f [2] 2a 97 [2] 6d 95 [2] 2a 84 [2] 64 88 [2] 68 82 [2] 7f 89 [2] 64 c7 [2] 59 }

  condition:
    any of them
}