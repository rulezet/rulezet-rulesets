rule TTP_XOR_MULT_DOSStub_68f9 {
  strings:
    $key_68f9 = { 3c 91 [2] 48 89 [2] 0f 8b [2] 48 9a [2] 06 96 [2] 0a 9c [2] 1d 97 [2] 06 d9 [2] 3b }

  condition:
    any of them
}