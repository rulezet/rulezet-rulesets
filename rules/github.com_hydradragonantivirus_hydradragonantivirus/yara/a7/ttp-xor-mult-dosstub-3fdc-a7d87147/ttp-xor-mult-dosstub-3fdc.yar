rule TTP_XOR_MULT_DOSStub_3fdc {
  strings:
    $key_3fdc = { 6b b4 [2] 1f ac [2] 58 ae [2] 1f bf [2] 51 b3 [2] 5d b9 [2] 4a b2 [2] 51 fc [2] 6c }

  condition:
    any of them
}