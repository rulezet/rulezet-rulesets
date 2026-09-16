rule TTP_XOR_MULT_DOSStub_eafc {
  strings:
    $key_eafc = { be 94 [2] ca 8c [2] 8d 8e [2] ca 9f [2] 84 93 [2] 88 99 [2] 9f 92 [2] 84 dc [2] b9 }

  condition:
    any of them
}