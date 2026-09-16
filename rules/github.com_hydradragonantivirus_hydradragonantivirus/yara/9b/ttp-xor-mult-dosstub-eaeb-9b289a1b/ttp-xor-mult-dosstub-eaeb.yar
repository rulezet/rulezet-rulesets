rule TTP_XOR_MULT_DOSStub_eaeb {
  strings:
    $key_eaeb = { be 83 [2] ca 9b [2] 8d 99 [2] ca 88 [2] 84 84 [2] 88 8e [2] 9f 85 [2] 84 cb [2] b9 }

  condition:
    any of them
}