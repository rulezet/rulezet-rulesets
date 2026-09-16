rule TTP_XOR_MULT_DOSStub_0771 {
  strings:
    $key_0771 = { 53 19 [2] 27 01 [2] 60 03 [2] 27 12 [2] 69 1e [2] 65 14 [2] 72 1f [2] 69 51 [2] 54 }

  condition:
    any of them
}