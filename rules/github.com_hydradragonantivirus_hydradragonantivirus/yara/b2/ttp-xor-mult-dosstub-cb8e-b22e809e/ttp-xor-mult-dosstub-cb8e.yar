rule TTP_XOR_MULT_DOSStub_cb8e {
  strings:
    $key_cb8e = { 9f e6 [2] eb fe [2] ac fc [2] eb ed [2] a5 e1 [2] a9 eb [2] be e0 [2] a5 ae [2] 98 }

  condition:
    any of them
}