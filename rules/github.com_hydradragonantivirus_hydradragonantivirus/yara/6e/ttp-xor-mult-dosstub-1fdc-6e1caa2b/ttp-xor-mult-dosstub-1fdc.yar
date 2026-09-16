rule TTP_XOR_MULT_DOSStub_1fdc {
  strings:
    $key_1fdc = { 4b b4 [2] 3f ac [2] 78 ae [2] 3f bf [2] 71 b3 [2] 7d b9 [2] 6a b2 [2] 71 fc [2] 4c }

  condition:
    any of them
}