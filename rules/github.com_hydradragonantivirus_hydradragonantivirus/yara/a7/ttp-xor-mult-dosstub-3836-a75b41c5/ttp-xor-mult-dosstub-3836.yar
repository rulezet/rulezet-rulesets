rule TTP_XOR_MULT_DOSStub_3836 {
  strings:
    $key_3836 = { 6c 5e [2] 18 46 [2] 5f 44 [2] 18 55 [2] 56 59 [2] 5a 53 [2] 4d 58 [2] 56 16 [2] 6b }

  condition:
    any of them
}