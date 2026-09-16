rule TTP_XOR_MULT_DOSStub_4ddc {
  strings:
    $key_4ddc = { 19 b4 [2] 6d ac [2] 2a ae [2] 6d bf [2] 23 b3 [2] 2f b9 [2] 38 b2 [2] 23 fc [2] 1e }

  condition:
    any of them
}