rule TTP_XOR_MULT_DOSStub_eae7 {
  strings:
    $key_eae7 = { be 8f [2] ca 97 [2] 8d 95 [2] ca 84 [2] 84 88 [2] 88 82 [2] 9f 89 [2] 84 c7 [2] b9 }

  condition:
    any of them
}