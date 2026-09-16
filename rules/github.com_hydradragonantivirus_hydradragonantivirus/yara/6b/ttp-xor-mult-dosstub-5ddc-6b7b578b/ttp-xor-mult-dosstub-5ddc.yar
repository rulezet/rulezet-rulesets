rule TTP_XOR_MULT_DOSStub_5ddc {
  strings:
    $key_5ddc = { 09 b4 [2] 7d ac [2] 3a ae [2] 7d bf [2] 33 b3 [2] 3f b9 [2] 28 b2 [2] 33 fc [2] 0e }

  condition:
    any of them
}