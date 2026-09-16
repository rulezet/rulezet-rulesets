rule TTP_XOR_MULT_DOSStub_eaf9 {
  strings:
    $key_eaf9 = { be 91 [2] ca 89 [2] 8d 8b [2] ca 9a [2] 84 96 [2] 88 9c [2] 9f 97 [2] 84 d9 [2] b9 }

  condition:
    any of them
}