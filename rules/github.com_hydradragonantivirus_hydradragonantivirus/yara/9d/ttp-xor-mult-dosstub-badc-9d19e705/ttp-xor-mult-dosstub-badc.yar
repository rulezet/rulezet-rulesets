rule TTP_XOR_MULT_DOSStub_badc {
  strings:
    $key_badc = { ee b4 [2] 9a ac [2] dd ae [2] 9a bf [2] d4 b3 [2] d8 b9 [2] cf b2 [2] d4 fc [2] e9 }

  condition:
    any of them
}