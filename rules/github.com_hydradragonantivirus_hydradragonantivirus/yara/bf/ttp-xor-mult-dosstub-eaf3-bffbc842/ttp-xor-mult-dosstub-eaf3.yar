rule TTP_XOR_MULT_DOSStub_eaf3 {
  strings:
    $key_eaf3 = { be 9b [2] ca 83 [2] 8d 81 [2] ca 90 [2] 84 9c [2] 88 96 [2] 9f 9d [2] 84 d3 [2] b9 }

  condition:
    any of them
}