rule TTP_XOR_MULT_DOSStub_3840 {
  strings:
    $key_3840 = { 6c 28 [2] 18 30 [2] 5f 32 [2] 18 23 [2] 56 2f [2] 5a 25 [2] 4d 2e [2] 56 60 [2] 6b }

  condition:
    any of them
}