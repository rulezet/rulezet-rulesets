rule TTP_XOR_MULT_DOSStub_3806 {
  strings:
    $key_3806 = { 6c 6e [2] 18 76 [2] 5f 74 [2] 18 65 [2] 56 69 [2] 5a 63 [2] 4d 68 [2] 56 26 [2] 6b }

  condition:
    any of them
}