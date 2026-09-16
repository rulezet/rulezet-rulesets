rule TTP_XOR_MULT_DOSStub_0211 {
  strings:
    $key_0211 = { 56 79 [2] 22 61 [2] 65 63 [2] 22 72 [2] 6c 7e [2] 60 74 [2] 77 7f [2] 6c 31 [2] 51 }

  condition:
    any of them
}