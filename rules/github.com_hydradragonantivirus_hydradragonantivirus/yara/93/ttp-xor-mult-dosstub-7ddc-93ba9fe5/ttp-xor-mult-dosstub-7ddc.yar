rule TTP_XOR_MULT_DOSStub_7ddc {
  strings:
    $key_7ddc = { 29 b4 [2] 5d ac [2] 1a ae [2] 5d bf [2] 13 b3 [2] 1f b9 [2] 08 b2 [2] 13 fc [2] 2e }

  condition:
    any of them
}