rule TTP_XOR_MULT_DOSStub_3c38 {
  strings:
    $key_3c38 = { 68 50 [2] 1c 48 [2] 5b 4a [2] 1c 5b [2] 52 57 [2] 5e 5d [2] 49 56 [2] 52 18 [2] 6f }

  condition:
    any of them
}