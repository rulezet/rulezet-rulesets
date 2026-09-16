rule TTP_XOR_MULT_DOSStub_ea0f {
  strings:
    $key_ea0f = { be 67 [2] ca 7f [2] 8d 7d [2] ca 6c [2] 84 60 [2] 88 6a [2] 9f 61 [2] 84 2f [2] b9 }

  condition:
    any of them
}