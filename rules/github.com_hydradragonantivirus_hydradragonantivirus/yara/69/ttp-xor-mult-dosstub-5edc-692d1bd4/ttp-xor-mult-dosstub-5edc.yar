rule TTP_XOR_MULT_DOSStub_5edc {
  strings:
    $key_5edc = { 0a b4 [2] 7e ac [2] 39 ae [2] 7e bf [2] 30 b3 [2] 3c b9 [2] 2b b2 [2] 30 fc [2] 0d }

  condition:
    any of them
}