rule TTP_XOR_MULT_DOSStub_25f9 {
  strings:
    $key_25f9 = { 71 91 [2] 05 89 [2] 42 8b [2] 05 9a [2] 4b 96 [2] 47 9c [2] 50 97 [2] 4b d9 [2] 76 }

  condition:
    any of them
}