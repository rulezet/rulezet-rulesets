rule TTP_XOR_MULT_DOSStub_eaea {
  strings:
    $key_eaea = { be 82 [2] ca 9a [2] 8d 98 [2] ca 89 [2] 84 85 [2] 88 8f [2] 9f 84 [2] 84 ca [2] b9 }

  condition:
    any of them
}