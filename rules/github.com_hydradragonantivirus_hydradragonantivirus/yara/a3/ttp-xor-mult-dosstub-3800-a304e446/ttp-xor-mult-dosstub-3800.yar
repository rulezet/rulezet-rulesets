rule TTP_XOR_MULT_DOSStub_3800 {
  strings:
    $key_3800 = { 6c 68 [2] 18 70 [2] 5f 72 [2] 18 63 [2] 56 6f [2] 5a 65 [2] 4d 6e [2] 56 20 [2] 6b }

  condition:
    any of them
}