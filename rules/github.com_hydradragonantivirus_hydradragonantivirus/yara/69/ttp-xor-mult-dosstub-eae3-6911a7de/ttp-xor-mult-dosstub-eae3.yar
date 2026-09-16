rule TTP_XOR_MULT_DOSStub_eae3 {
  strings:
    $key_eae3 = { be 8b [2] ca 93 [2] 8d 91 [2] ca 80 [2] 84 8c [2] 88 86 [2] 9f 8d [2] 84 c3 [2] b9 }

  condition:
    any of them
}