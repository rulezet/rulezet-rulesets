rule TTP_XOR_MULT_DOSStub_ea27 {
  strings:
    $key_ea27 = { be 4f [2] ca 57 [2] 8d 55 [2] ca 44 [2] 84 48 [2] 88 42 [2] 9f 49 [2] 84 07 [2] b9 }

  condition:
    any of them
}