rule TTP_XOR_MULT_DOSStub_0a21 {
  strings:
    $key_0a21 = { 5e 49 [2] 2a 51 [2] 6d 53 [2] 2a 42 [2] 64 4e [2] 68 44 [2] 7f 4f [2] 64 01 [2] 59 }

  condition:
    any of them
}