rule TTP_XOR_MULT_DOSStub_3201 {
  strings:
    $key_3201 = { 66 69 [2] 12 71 [2] 55 73 [2] 12 62 [2] 5c 6e [2] 50 64 [2] 47 6f [2] 5c 21 [2] 61 }

  condition:
    any of them
}