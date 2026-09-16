rule TTP_XOR_MULT_DOSStub_0f36 {
  strings:
    $key_0f36 = { 5b 5e [2] 2f 46 [2] 68 44 [2] 2f 55 [2] 61 59 [2] 6d 53 [2] 7a 58 [2] 61 16 [2] 5c }

  condition:
    any of them
}