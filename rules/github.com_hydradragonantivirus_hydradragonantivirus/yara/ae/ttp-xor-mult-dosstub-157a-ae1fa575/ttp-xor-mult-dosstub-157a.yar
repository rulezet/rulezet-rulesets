rule TTP_XOR_MULT_DOSStub_157a {
  strings:
    $key_157a = { 41 12 [2] 35 0a [2] 72 08 [2] 35 19 [2] 7b 15 [2] 77 1f [2] 60 14 [2] 7b 5a [2] 46 }

  condition:
    any of them
}