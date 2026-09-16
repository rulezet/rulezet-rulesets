rule TTP_XOR_MULT_DOSStub_0ae1 {
  strings:
    $key_0ae1 = { 5e 89 [2] 2a 91 [2] 6d 93 [2] 2a 82 [2] 64 8e [2] 68 84 [2] 7f 8f [2] 64 c1 [2] 59 }

  condition:
    any of them
}