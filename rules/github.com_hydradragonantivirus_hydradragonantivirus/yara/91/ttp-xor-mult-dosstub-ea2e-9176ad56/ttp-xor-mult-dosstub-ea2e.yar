rule TTP_XOR_MULT_DOSStub_ea2e {
  strings:
    $key_ea2e = { be 46 [2] ca 5e [2] 8d 5c [2] ca 4d [2] 84 41 [2] 88 4b [2] 9f 40 [2] 84 0e [2] b9 }

  condition:
    any of them
}