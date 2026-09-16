rule TTP_XOR_MULT_DOSStub_cddc {
  strings:
    $key_cddc = { 99 b4 [2] ed ac [2] aa ae [2] ed bf [2] a3 b3 [2] af b9 [2] b8 b2 [2] a3 fc [2] 9e }

  condition:
    any of them
}