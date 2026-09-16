rule TTP_XOR_MULT_DOSStub_3cf4 {
  strings:
    $key_3cf4 = { 68 9c [2] 1c 84 [2] 5b 86 [2] 1c 97 [2] 52 9b [2] 5e 91 [2] 49 9a [2] 52 d4 [2] 6f }

  condition:
    any of them
}