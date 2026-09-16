rule TTP_XOR_MULT_DOSStub_3851 {
  strings:
    $key_3851 = { 6c 39 [2] 18 21 [2] 5f 23 [2] 18 32 [2] 56 3e [2] 5a 34 [2] 4d 3f [2] 56 71 [2] 6b }

  condition:
    any of them
}