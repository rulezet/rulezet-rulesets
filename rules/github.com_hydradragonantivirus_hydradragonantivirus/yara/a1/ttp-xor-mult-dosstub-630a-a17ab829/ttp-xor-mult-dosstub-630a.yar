rule TTP_XOR_MULT_DOSStub_630a {
  strings:
    $key_630a = { 37 62 [2] 43 7a [2] 04 78 [2] 43 69 [2] 0d 65 [2] 01 6f [2] 16 64 [2] 0d 2a [2] 30 }

  condition:
    any of them
}