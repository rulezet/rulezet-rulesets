rule TTP_XOR_MULT_DOSStub_addc {
  strings:
    $key_addc = { f9 b4 [2] 8d ac [2] ca ae [2] 8d bf [2] c3 b3 [2] cf b9 [2] d8 b2 [2] c3 fc [2] fe }

  condition:
    any of them
}