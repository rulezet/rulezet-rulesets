rule TTP_XOR_MULT_DOSStub_0627 {
  strings:
    $key_0627 = { 52 4f [2] 26 57 [2] 61 55 [2] 26 44 [2] 68 48 [2] 64 42 [2] 73 49 [2] 68 07 [2] 55 }

  condition:
    any of them
}