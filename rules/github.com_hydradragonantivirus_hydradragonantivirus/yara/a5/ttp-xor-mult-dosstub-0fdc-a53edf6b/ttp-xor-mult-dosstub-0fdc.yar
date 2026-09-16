rule TTP_XOR_MULT_DOSStub_0fdc {
  strings:
    $key_0fdc = { 5b b4 [2] 2f ac [2] 68 ae [2] 2f bf [2] 61 b3 [2] 6d b9 [2] 7a b2 [2] 61 fc [2] 5c }

  condition:
    any of them
}