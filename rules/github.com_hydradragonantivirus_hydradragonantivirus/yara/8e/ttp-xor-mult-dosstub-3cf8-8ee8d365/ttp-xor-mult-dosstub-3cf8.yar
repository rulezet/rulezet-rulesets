rule TTP_XOR_MULT_DOSStub_3cf8 {
  strings:
    $key_3cf8 = { 68 90 [2] 1c 88 [2] 5b 8a [2] 1c 9b [2] 52 97 [2] 5e 9d [2] 49 96 [2] 52 d8 [2] 6f }

  condition:
    any of them
}