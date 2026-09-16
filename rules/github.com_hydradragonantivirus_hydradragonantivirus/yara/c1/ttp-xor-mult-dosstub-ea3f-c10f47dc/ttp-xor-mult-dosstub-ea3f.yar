rule TTP_XOR_MULT_DOSStub_ea3f {
  strings:
    $key_ea3f = { be 57 [2] ca 4f [2] 8d 4d [2] ca 5c [2] 84 50 [2] 88 5a [2] 9f 51 [2] 84 1f [2] b9 }

  condition:
    any of them
}