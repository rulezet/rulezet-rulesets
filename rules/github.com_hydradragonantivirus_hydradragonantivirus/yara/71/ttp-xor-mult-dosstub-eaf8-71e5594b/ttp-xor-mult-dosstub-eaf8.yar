rule TTP_XOR_MULT_DOSStub_eaf8 {
  strings:
    $key_eaf8 = { be 90 [2] ca 88 [2] 8d 8a [2] ca 9b [2] 84 97 [2] 88 9d [2] 9f 96 [2] 84 d8 [2] b9 }

  condition:
    any of them
}