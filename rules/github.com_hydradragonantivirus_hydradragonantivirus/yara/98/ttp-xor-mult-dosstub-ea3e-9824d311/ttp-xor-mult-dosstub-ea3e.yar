rule TTP_XOR_MULT_DOSStub_ea3e {
  strings:
    $key_ea3e = { be 56 [2] ca 4e [2] 8d 4c [2] ca 5d [2] 84 51 [2] 88 5b [2] 9f 50 [2] 84 1e [2] b9 }

  condition:
    any of them
}