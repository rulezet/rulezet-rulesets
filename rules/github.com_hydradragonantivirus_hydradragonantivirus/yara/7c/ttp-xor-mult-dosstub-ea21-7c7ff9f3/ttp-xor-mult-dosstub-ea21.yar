rule TTP_XOR_MULT_DOSStub_ea21 {
  strings:
    $key_ea21 = { be 49 [2] ca 51 [2] 8d 53 [2] ca 42 [2] 84 4e [2] 88 44 [2] 9f 4f [2] 84 01 [2] b9 }

  condition:
    any of them
}