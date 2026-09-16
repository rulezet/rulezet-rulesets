rule TTP_XOR_MULT_DOSStub_7151 {
  strings:
    $key_7151 = { 25 39 [2] 51 21 [2] 16 23 [2] 51 32 [2] 1f 3e [2] 13 34 [2] 04 3f [2] 1f 71 [2] 22 }

  condition:
    any of them
}