rule TTP_XOR_MULT_DOSStub_eaee {
  strings:
    $key_eaee = { be 86 [2] ca 9e [2] 8d 9c [2] ca 8d [2] 84 81 [2] 88 8b [2] 9f 80 [2] 84 ce [2] b9 }

  condition:
    any of them
}