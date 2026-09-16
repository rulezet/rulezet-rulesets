rule TTP_XOR_MULT_DOSStub_5c18 {
  strings:
    $key_5c18 = { 08 70 [2] 7c 68 [2] 3b 6a [2] 7c 7b [2] 32 77 [2] 3e 7d [2] 29 76 [2] 32 38 [2] 0f }

  condition:
    any of them
}