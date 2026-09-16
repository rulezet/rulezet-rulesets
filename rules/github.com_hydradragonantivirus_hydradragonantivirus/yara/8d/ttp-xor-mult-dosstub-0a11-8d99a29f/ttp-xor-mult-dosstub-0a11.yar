rule TTP_XOR_MULT_DOSStub_0a11 {
  strings:
    $key_0a11 = { 5e 79 [2] 2a 61 [2] 6d 63 [2] 2a 72 [2] 64 7e [2] 68 74 [2] 7f 7f [2] 64 31 [2] 59 }

  condition:
    any of them
}