rule TTP_XOR_MULT_DOSStub_4cf4 {
  strings:
    $key_4cf4 = { 18 9c [2] 6c 84 [2] 2b 86 [2] 6c 97 [2] 22 9b [2] 2e 91 [2] 39 9a [2] 22 d4 [2] 1f }

  condition:
    any of them
}