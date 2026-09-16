rule TTP_XOR_MULT_DOSStub_5fdc {
  strings:
    $key_5fdc = { 0b b4 [2] 7f ac [2] 38 ae [2] 7f bf [2] 31 b3 [2] 3d b9 [2] 2a b2 [2] 31 fc [2] 0c }

  condition:
    any of them
}