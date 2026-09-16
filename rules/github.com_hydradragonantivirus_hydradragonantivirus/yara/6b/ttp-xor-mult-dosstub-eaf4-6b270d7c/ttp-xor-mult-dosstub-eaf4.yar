rule TTP_XOR_MULT_DOSStub_eaf4 {
  strings:
    $key_eaf4 = { be 9c [2] ca 84 [2] 8d 86 [2] ca 97 [2] 84 9b [2] 88 91 [2] 9f 9a [2] 84 d4 [2] b9 }

  condition:
    any of them
}