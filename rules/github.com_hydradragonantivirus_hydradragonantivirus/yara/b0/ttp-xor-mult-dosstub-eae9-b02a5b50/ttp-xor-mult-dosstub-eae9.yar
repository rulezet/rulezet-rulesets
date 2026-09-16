rule TTP_XOR_MULT_DOSStub_eae9 {
  strings:
    $key_eae9 = { be 81 [2] ca 99 [2] 8d 9b [2] ca 8a [2] 84 86 [2] 88 8c [2] 9f 87 [2] 84 c9 [2] b9 }

  condition:
    any of them
}