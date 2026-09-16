rule TTP_XOR_MULT_DOSStub_3cf9 {
  strings:
    $key_3cf9 = { 68 91 [2] 1c 89 [2] 5b 8b [2] 1c 9a [2] 52 96 [2] 5e 9c [2] 49 97 [2] 52 d9 [2] 6f }

  condition:
    any of them
}