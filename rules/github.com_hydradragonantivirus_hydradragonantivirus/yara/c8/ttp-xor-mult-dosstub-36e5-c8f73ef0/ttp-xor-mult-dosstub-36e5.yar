rule TTP_XOR_MULT_DOSStub_36e5 {
  strings:
    $key_36e5 = { 62 8d [2] 16 95 [2] 51 97 [2] 16 86 [2] 58 8a [2] 54 80 [2] 43 8b [2] 58 c5 [2] 65 }

  condition:
    any of them
}