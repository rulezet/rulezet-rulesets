rule TTP_XOR_MULT_DOSStub_88ba {
  strings:
    $key_88ba = { dc d2 [2] a8 ca [2] ef c8 [2] a8 d9 [2] e6 d5 [2] ea df [2] fd d4 [2] e6 9a [2] db }

  condition:
    any of them
}