rule TTP_XOR_MULT_DOSStub_eaef {
  strings:
    $key_eaef = { be 87 [2] ca 9f [2] 8d 9d [2] ca 8c [2] 84 80 [2] 88 8a [2] 9f 81 [2] 84 cf [2] b9 }

  condition:
    any of them
}