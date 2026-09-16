rule TTP_XOR_MULT_DOSStub_0f11 {
  strings:
    $key_0f11 = { 5b 79 [2] 2f 61 [2] 68 63 [2] 2f 72 [2] 61 7e [2] 6d 74 [2] 7a 7f [2] 61 31 [2] 5c }

  condition:
    any of them
}