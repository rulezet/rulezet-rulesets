rule TTP_XOR_MULT_DOSStub_88cb {
  strings:
    $key_88cb = { dc a3 [2] a8 bb [2] ef b9 [2] a8 a8 [2] e6 a4 [2] ea ae [2] fd a5 [2] e6 eb [2] db }

  condition:
    any of them
}