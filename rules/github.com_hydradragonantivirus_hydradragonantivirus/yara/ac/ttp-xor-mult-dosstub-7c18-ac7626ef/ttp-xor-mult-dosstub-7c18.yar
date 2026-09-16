rule TTP_XOR_MULT_DOSStub_7c18 {
  strings:
    $key_7c18 = { 28 70 [2] 5c 68 [2] 1b 6a [2] 5c 7b [2] 12 77 [2] 1e 7d [2] 09 76 [2] 12 38 [2] 2f }

  condition:
    any of them
}