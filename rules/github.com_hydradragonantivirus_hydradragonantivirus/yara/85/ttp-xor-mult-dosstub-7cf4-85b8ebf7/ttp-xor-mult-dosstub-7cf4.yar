rule TTP_XOR_MULT_DOSStub_7cf4 {
  strings:
    $key_7cf4 = { 28 9c [2] 5c 84 [2] 1b 86 [2] 5c 97 [2] 12 9b [2] 1e 91 [2] 09 9a [2] 12 d4 [2] 2f }

  condition:
    any of them
}