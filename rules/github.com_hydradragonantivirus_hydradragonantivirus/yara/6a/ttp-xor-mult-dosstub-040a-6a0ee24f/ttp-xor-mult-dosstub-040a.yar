rule TTP_XOR_MULT_DOSStub_040a {
  strings:
    $key_040a = { 50 62 [2] 24 7a [2] 63 78 [2] 24 69 [2] 6a 65 [2] 66 6f [2] 71 64 [2] 6a 2a [2] 57 }

  condition:
    any of them
}