rule TTP_XOR_MULT_DOSStub_eaec {
  strings:
    $key_eaec = { be 84 [2] ca 9c [2] 8d 9e [2] ca 8f [2] 84 83 [2] 88 89 [2] 9f 82 [2] 84 cc [2] b9 }

  condition:
    any of them
}