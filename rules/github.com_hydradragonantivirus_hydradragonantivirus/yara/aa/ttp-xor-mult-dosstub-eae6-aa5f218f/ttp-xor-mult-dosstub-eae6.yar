rule TTP_XOR_MULT_DOSStub_eae6 {
  strings:
    $key_eae6 = { be 8e [2] ca 96 [2] 8d 94 [2] ca 85 [2] 84 89 [2] 88 83 [2] 9f 88 [2] 84 c6 [2] b9 }

  condition:
    any of them
}