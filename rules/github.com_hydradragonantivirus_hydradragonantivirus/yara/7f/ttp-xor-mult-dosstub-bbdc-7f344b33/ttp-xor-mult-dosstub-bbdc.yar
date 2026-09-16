rule TTP_XOR_MULT_DOSStub_bbdc {
  strings:
    $key_bbdc = { ef b4 [2] 9b ac [2] dc ae [2] 9b bf [2] d5 b3 [2] d9 b9 [2] ce b2 [2] d5 fc [2] e8 }

  condition:
    any of them
}