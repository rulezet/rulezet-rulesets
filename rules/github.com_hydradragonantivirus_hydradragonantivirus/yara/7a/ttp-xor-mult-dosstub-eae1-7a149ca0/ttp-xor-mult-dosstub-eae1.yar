rule TTP_XOR_MULT_DOSStub_eae1 {
  strings:
    $key_eae1 = { be 89 [2] ca 91 [2] 8d 93 [2] ca 82 [2] 84 8e [2] 88 84 [2] 9f 8f [2] 84 c1 [2] b9 }

  condition:
    any of them
}