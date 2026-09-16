rule TTP_XOR_MULT_DOSStub_ea23 {
  strings:
    $key_ea23 = { be 4b [2] ca 53 [2] 8d 51 [2] ca 40 [2] 84 4c [2] 88 46 [2] 9f 4d [2] 84 03 [2] b9 }

  condition:
    any of them
}