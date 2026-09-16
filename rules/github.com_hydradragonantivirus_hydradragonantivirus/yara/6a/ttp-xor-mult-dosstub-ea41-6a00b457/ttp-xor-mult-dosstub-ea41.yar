rule TTP_XOR_MULT_DOSStub_ea41 {
  strings:
    $key_ea41 = { be 29 [2] ca 31 [2] 8d 33 [2] ca 22 [2] 84 2e [2] 88 24 [2] 9f 2f [2] 84 61 [2] b9 }

  condition:
    any of them
}