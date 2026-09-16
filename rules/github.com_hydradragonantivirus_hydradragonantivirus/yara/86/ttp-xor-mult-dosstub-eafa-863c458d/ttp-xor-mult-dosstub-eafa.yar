rule TTP_XOR_MULT_DOSStub_eafa {
  strings:
    $key_eafa = { be 92 [2] ca 8a [2] 8d 88 [2] ca 99 [2] 84 95 [2] 88 9f [2] 9f 94 [2] 84 da [2] b9 }

  condition:
    any of them
}