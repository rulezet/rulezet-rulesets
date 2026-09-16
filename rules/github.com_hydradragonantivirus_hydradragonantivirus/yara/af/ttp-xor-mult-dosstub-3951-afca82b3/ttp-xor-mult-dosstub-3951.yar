rule TTP_XOR_MULT_DOSStub_3951 {
  strings:
    $key_3951 = { 6d 39 [2] 19 21 [2] 5e 23 [2] 19 32 [2] 57 3e [2] 5b 34 [2] 4c 3f [2] 57 71 [2] 6a }

  condition:
    any of them
}