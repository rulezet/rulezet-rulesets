rule TTP_XOR_MULT_DOSStub_cbcd {
  strings:
    $key_cbcd = { 9f a5 [2] eb bd [2] ac bf [2] eb ae [2] a5 a2 [2] a9 a8 [2] be a3 [2] a5 ed [2] 98 }

  condition:
    any of them
}