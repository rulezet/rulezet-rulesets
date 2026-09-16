rule TTP_XOR_MULT_DOSStub_ba9e {
  strings:
    $key_ba9e = { ee f6 [2] 9a ee [2] dd ec [2] 9a fd [2] d4 f1 [2] d8 fb [2] cf f0 [2] d4 be [2] e9 }

  condition:
    any of them
}